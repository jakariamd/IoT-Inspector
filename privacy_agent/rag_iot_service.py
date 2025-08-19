import requests
from pathlib import Path
import logging
import pandas as pd
import numpy as np
import os
from typing import List, Dict, Optional, Any, Union
import threading
import sys
import importlib
import json
import socket
import time
from multiprocessing import Process, Queue, Pipe
import argparse
from datetime import datetime
import signal
from concurrent.futures import ThreadPoolExecutor, as_completed
import queue

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Configuration
HEADERS = {'User-Agent': 'Mozilla/5.0 (RAG-Research-Demo)'}
MODEL_NAME = 'sentence-transformers/all-MiniLM-L6-v2'
EMBED_DIM = 384
TOP_K = 5

# Enhanced service configuration
DEFAULT_HOST = 'localhost'
DEFAULT_PORT = 8899
SOCKET_TIMEOUT = 300  # seconds
MAX_WORKERS = 4  # Number of worker threads for processing queries
MAX_QUEUE_SIZE = 50  # Maximum number of queued requests
LISTEN_BACKLOG = 20  # Increased socket listen queue

# Use relative path that works from project root
DATA_DIR = Path(__file__).parent / 'rag_iot_data' / 'device_database'
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Module loading state
_modules_loaded = {
    'faiss': None,
    'sentence_transformers': None,
    'transformers': None
}

def _safe_import_module(module_name: str, attribute: str = None) -> Union[Any, None]:
    """Safely import a module without triggering PyTorch loading issues"""
    try:
        if _modules_loaded.get(module_name) is None:
            # Use importlib to avoid direct import statements
            module = importlib.import_module(module_name)
            _modules_loaded[module_name] = module
        
        if attribute:
            return getattr(_modules_loaded[module_name], attribute)
        return _modules_loaded[module_name]
    except Exception as e:
        logger.warning(f"Failed to import {module_name}: {e}")
        return None

def _get_faiss():
    """Safely get faiss module"""
    return _safe_import_module('faiss')

def _get_sentence_transformer_class():
    """Safely get SentenceTransformer class"""
    return _safe_import_module('sentence_transformers', 'SentenceTransformer')

class OllamaConfig:
    """Configuration for Ollama LLM service"""
    
    def __init__(self):
        self.ollama_url = os.getenv('OLLAMA_URL', 'http://localhost:11434')
        self.model_name = os.getenv('LLM_MODEL', 'llama3:latest')
        self.timeout = int(os.getenv('LLM_TIMEOUT', '120'))  # Increased timeout
        self.max_retries = int(os.getenv('LLM_MAX_RETRIES', '3'))
    
    def is_available(self) -> bool:
        """Check if Ollama is running and accessible"""
        try:
            response = requests.get(f"{self.ollama_url}/api/tags", timeout=5)
            return response.status_code == 200
        except Exception:
            return False
    
    def get_available_models(self) -> List[str]:
        """Get list of available models from Ollama"""
        try:
            response = requests.get(f"{self.ollama_url}/api/tags", timeout=5)
            if response.status_code == 200:
                models = response.json().get('models', [])
                return [model['name'] for model in models]
        except Exception:
            return []
        return []

class ThreadSafeRAGSystem:
    """Thread-safe RAG System with connection pooling"""
    
    def __init__(self, num_workers: int = MAX_WORKERS):
        self.ollama_config = OllamaConfig()
        self.ollama_available = False
        self.df: Optional[pd.DataFrame] = None
        self.index: Optional[Any] = None
        self.embeddings: Optional[np.ndarray] = None
        self.artifacts_loaded = False
        self.lock = threading.RLock()  # Reentrant lock
        self.sentence_transformers: List[Any] = []  # Pool of models
        self._ollama_checked = False
        self._models_loaded = False
        self.num_workers = num_workers
        self.model_pool_lock = threading.Lock()
        
    def _check_ollama_availability(self):
        """Check Ollama availability only when needed"""
        if not self._ollama_checked:
            with self.lock:
                if not self._ollama_checked:
                    self.ollama_available = self.ollama_config.is_available()
                    self._ollama_checked = True
    
    def _load_ml_models(self) -> bool:
        """Load ML models pool for concurrent access"""
        if self._models_loaded:
            return True
        
        with self.lock:
            if self._models_loaded:
                return True
                
            try:
                # Load SentenceTransformer class
                SentenceTransformer = _get_sentence_transformer_class()
                if SentenceTransformer is None:
                    raise ImportError("SentenceTransformer not available")
                
                # Create pool of models for concurrent access
                logger.info(f"Loading {self.num_workers} SentenceTransformer models...")
                for i in range(self.num_workers):
                    model = SentenceTransformer(MODEL_NAME)
                    self.sentence_transformers.append(model)
                    logger.info(f"✅ Model {i+1}/{self.num_workers} loaded")
                
                self._models_loaded = True
                logger.info(f"✅ All {self.num_workers} ML models loaded successfully")
                return True
                
            except Exception as e:
                logger.error(f"Failed to load ML models: {e}")
                return False
    
    def _get_model(self):
        """Get a model from the pool (thread-safe)"""
        with self.model_pool_lock:
            if self.sentence_transformers:
                return self.sentence_transformers.pop()
        return None
    
    def _return_model(self, model):
        """Return a model to the pool"""
        with self.model_pool_lock:
            self.sentence_transformers.append(model)
    
    def _load_artifacts(self) -> bool:
        """Load the RAG artifacts (corpus, index, embeddings)"""
        try:
            corpus_path = DATA_DIR / 'corpus.parquet'
            index_path = DATA_DIR / 'index.faiss'
            embeddings_path = DATA_DIR / 'embeddings.npy'
            
            # Check if files exist
            missing_files = []
            for path in [corpus_path, index_path, embeddings_path]:
                if not path.exists():
                    missing_files.append(str(path))
            
            if missing_files:
                raise FileNotFoundError(f"Missing RAG artifacts: {missing_files}")
            
            # Load pandas dataframe first (no ML dependencies)
            self.df = pd.read_parquet(corpus_path)
            logger.info(f"✅ Loaded corpus with {len(self.df)} chunks")
            
            # Load numpy embeddings
            self.embeddings = np.load(embeddings_path)
            logger.info(f"✅ Loaded embeddings with shape {self.embeddings.shape}")
            
            # Load faiss index (this may trigger some PyTorch dependencies)
            faiss = _get_faiss()
            if faiss is None:
                raise ImportError("FAISS not available")
            
            self.index = faiss.read_index(str(index_path))
            logger.info("✅ FAISS index loaded successfully")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to load RAG artifacts: {e}")
            return False
    
    def initialize(self, load_models: bool = True) -> bool:
        """Initialize the RAG system"""
        with self.lock:
            if self.artifacts_loaded:
                logger.info("RAG system already initialized")
                return True
            
            try:
                # Load artifacts first
                if not self._load_artifacts():
                    return False
                
                # Load ML models by default for service mode
                if load_models:
                    if not self._load_ml_models():
                        logger.warning("Failed to load ML models")
                        return False
                
                self.artifacts_loaded = True
                logger.info("✅ RAG system initialized")
                return True
                
            except Exception as e:
                logger.error(f"Failed to initialize RAG system: {e}")
                return False
    
    def _call_ollama(self, prompt: str, system_prompt: str = None) -> str:
        """Call Ollama API with proper error handling"""
        self._check_ollama_availability()
        
        if not self.ollama_available:
            return "❌ Ollama is not available. Please start Ollama and ensure the model is installed."
        
        for attempt in range(self.ollama_config.max_retries):
            try:
                if system_prompt:
                    url = f"{self.ollama_config.ollama_url}/api/chat"
                    payload = {
                        "model": self.ollama_config.model_name,
                        "messages": [
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": prompt}
                        ],
                        "stream": False,
                        "options": {
                            "temperature": 0.2,
                            "top_p": 0.9,
                            "num_predict": 600
                        }
                    }
                else:
                    url = f"{self.ollama_config.ollama_url}/api/generate"
                    payload = {
                        "model": self.ollama_config.model_name,
                        "prompt": prompt,
                        "stream": False,
                        "options": {
                            "temperature": 0.2,
                            "top_p": 0.9,
                            "num_predict": 600
                        }
                    }
                
                response = requests.post(url, json=payload, timeout=self.ollama_config.timeout)
                response.raise_for_status()
                result = response.json()
                
                if system_prompt:
                    return result.get('message', {}).get('content', 'No response').strip()
                else:
                    return result.get('response', 'No response').strip()
                    
            except requests.exceptions.ConnectionError:
                if attempt == self.ollama_config.max_retries - 1:
                    return f"❌ Could not connect to Ollama at {self.ollama_config.ollama_url}"
            except requests.exceptions.Timeout:
                if attempt == self.ollama_config.max_retries - 1:
                    return "❌ Request timed out"
            except Exception as e:
                if attempt == self.ollama_config.max_retries - 1:
                    return f"❌ Error: {str(e)}"
        
        return "❌ All retry attempts failed"
    
    def _retrieve(self, query: str, k: int = TOP_K) -> pd.DataFrame:
        """Retrieve relevant chunks for a query (thread-safe)"""
        if not self.artifacts_loaded:
            raise RuntimeError("RAG system not initialized")
        
        # Get a model from the pool
        model = self._get_model()
        if model is None:
            raise RuntimeError("No available models in pool")
        
        try:
            # Encode query
            q_emb = model.encode([query], convert_to_numpy=True, normalize_embeddings=True)
            
            # Search index (FAISS operations are thread-safe for read-only access)
            with self.lock:
                D, I = self.index.search(q_emb, k)
            
            # Get results
            hits = self.df.iloc[I[0]].copy()
            hits['score'] = D[0]
            return hits[['score', 'device', 'brand', 'kind', 'url', 'chunk_id', 'text']]
            
        finally:
            # Always return the model to the pool
            self._return_model(model)
    
    def _synthesize_answer(self, query: str, hits: pd.DataFrame) -> str:
        """Generate answer from retrieved chunks"""
        context_blocks = []
        for _, row in hits.iterrows():
            cite = f"[{row['device']} | {row['kind']} | {row['url']}]"
            context_blocks.append(f"SOURCE: {cite}\n{row['text']}")
        context_text = '\n\n'.join(context_blocks)

        self._check_ollama_availability()
        
        if self.ollama_available:
            system_prompt = (
                "You are a careful assistant analyzing IoT device privacy policies and product information. "
                "Answer only using the provided sources. Cite sources inline after each relevant claim using "
                "[device | kind | url] format. If information is missing or unclear, explicitly state so. "
                "Be concise but thorough in your analysis."
            )
            
            user_prompt = f"""Question: {query}

Sources:
{context_text}

Please analyze the sources above to answer the question. Include inline citations and be specific about what each device does regarding the queried topic."""

            try:
                response = self._call_ollama(user_prompt, system_prompt)
                if response.startswith("❌"):
                    return f"{response}\n\n📚 Top passages for reference:\n\n{context_text}"
                return response
            except Exception as e:
                return f"❌ Generation error: {e}\n\n📚 Top passages:\n\n{context_text}"
        else:
            header = f"❌ Ollama not available. Showing top retrieved passages with citations.\n\n"
            return header + context_text
    
    def query(self, query: str) -> str:
        """
        Query the RAG system with a question about IoT devices (thread-safe).
        
        Args:
            query (str): The question to ask about IoT devices
            
        Returns:
            str: The synthesized answer with citations
        """
        if not self.artifacts_loaded:
            return "❌ RAG system not initialized"
        
        try:
            hits = self._retrieve(query, k=TOP_K)
            answer = self._synthesize_answer(query, hits)
            logger.info(f"RAG system query successful: {query[:50]}...")
            return answer
        except Exception as e:
            logger.error(f'❌ Error querying RAG system: {e}')
            return f"❌ Error processing query: {str(e)}"
    
    def get_status(self) -> Dict:
        """Get the current status of the RAG system"""
        self._check_ollama_availability()
        with self.model_pool_lock:
            available_models = len(self.sentence_transformers)
        
        return {
            "artifacts_loaded": self.artifacts_loaded,
            "models_loaded": self._models_loaded,
            "available_models": available_models,
            "total_models": self.num_workers,
            "ollama_available": self.ollama_available,
            "total_chunks": len(self.df) if self.df is not None else 0,
            "model_name": self.ollama_config.model_name,
            "ollama_url": self.ollama_config.ollama_url,
            "data_dir": str(DATA_DIR),
            "artifacts_exist": all(
                (DATA_DIR / f).exists() 
                for f in ['corpus.parquet', 'index.faiss', 'embeddings.npy']
            )
        }

class EnhancedRAGService:
    """Enhanced RAG Service with connection pooling and queue management"""
    
    def __init__(self, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT, max_workers: int = MAX_WORKERS):
        self.host = host
        self.port = port
        self.max_workers = max_workers
        self.rag_system = ThreadSafeRAGSystem(max_workers)
        self.running = False
        self.socket = None
        self.executor = ThreadPoolExecutor(max_workers=max_workers*2)  # More threads for I/O
        self.request_queue = queue.Queue(maxsize=MAX_QUEUE_SIZE)
        self.active_connections = 0
        self.stats_lock = threading.Lock()
        
    def initialize(self) -> bool:
        """Initialize the RAG service"""
        logger.info(f"🚀 Initializing enhanced RAG service with {self.max_workers} workers...")
        return self.rag_system.initialize(load_models=True)
    
    def _handle_request(self, data: Dict) -> Dict:
        """Handle a single request"""
        try:
            command = data.get('command')
            request_id = data.get('request_id', 'unknown')
            
            if command == 'query':
                query = data.get('query', '')
                if not query:
                    return {
                        'request_id': request_id,
                        'status': 'error',
                        'error': 'No query provided'
                    }
                
                # Process query with the thread-safe RAG system
                answer = self.rag_system.query(query)
                return {
                    'request_id': request_id,
                    'status': 'success',
                    'answer': answer,
                    'timestamp': datetime.now().isoformat()
                }
            
            elif command == 'status':
                status = self.rag_system.get_status()
                with self.stats_lock:
                    status['active_connections'] = self.active_connections
                    status['queue_size'] = self.request_queue.qsize()
                return {
                    'request_id': request_id,
                    'status': 'success',
                    'system_status': status,
                    'timestamp': datetime.now().isoformat()
                }
            
            elif command == 'ping':
                return {
                    'request_id': request_id,
                    'status': 'success',
                    'message': 'pong',
                    'timestamp': datetime.now().isoformat()
                }
            
            elif command == 'shutdown':
                logger.info("Shutdown command received")
                self.running = False
                return {
                    'request_id': request_id,
                    'status': 'success',
                    'message': 'Shutting down'
                }
            
            else:
                return {
                    'request_id': request_id,
                    'status': 'error',
                    'error': f'Unknown command: {command}'
                }
        
        except Exception as e:
            logger.error(f"Error handling request: {e}")
            return {
                'request_id': data.get('request_id', 'unknown'),
                'status': 'error',
                'error': str(e)
            }
    
    def start(self):
        """Start the enhanced RAG service"""
        if not self.initialize():
            logger.error("❌ Failed to initialize RAG service")
            return False
        
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.host, self.port))
            self.socket.listen(LISTEN_BACKLOG)  # Increased listen backlog
            self.running = True
            
            logger.info(f"🎯 Enhanced RAG service listening on {self.host}:{self.port}")
            logger.info(f"📊 Configuration: {self.max_workers} workers, {LISTEN_BACKLOG} listen backlog, {MAX_QUEUE_SIZE} queue size")
            
            while self.running:
                try:
                    client_socket, address = self.socket.accept()
                    logger.debug(f"Connection from {address}")
                    
                    # Submit client handling to thread pool
                    future = self.executor.submit(self._handle_client, client_socket)
                    
                except Exception as e:
                    if self.running:
                        logger.error(f"Error accepting connection: {e}")
                    
        except Exception as e:
            logger.error(f"Error starting service: {e}")
            return False
        finally:
            if self.socket:
                self.socket.close()
            self.executor.shutdown(wait=True)
            logger.info("Enhanced RAG service stopped")
    
    def _handle_client(self, client_socket):
        """Handle a client connection"""
        with self.stats_lock:
            self.active_connections += 1
            
        try:
            client_socket.settimeout(SOCKET_TIMEOUT)
            
            # Receive data
            data = b''
            while True:
                chunk = client_socket.recv(4096)
                if not chunk:
                    break
                data += chunk
                if b'\n' in data:  # Simple message delimiter
                    break
            
            if data:
                # Parse request
                message = data.decode('utf-8').strip()
                request_data = json.loads(message)
                
                # Process request
                response = self._handle_request(request_data)
                
                # Send response
                response_json = json.dumps(response) + '\n'
                client_socket.send(response_json.encode('utf-8'))
                
        except Exception as e:
            logger.error(f"Error handling client: {e}")
            error_response = {
                'status': 'error',
                'error': str(e)
            }
            try:
                client_socket.send(json.dumps(error_response).encode('utf-8'))
            except:
                pass
        finally:
            client_socket.close()
            with self.stats_lock:
                self.active_connections -= 1
    
    def stop(self):
        """Stop the RAG service"""
        self.running = False
        if self.socket:
            self.socket.close()
        self.executor.shutdown(wait=True)

# Update the service classes
RAGService = EnhancedRAGService

class RAGClient:
    """Client to communicate with RAG service"""
    
    def __init__(self, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT):
        self.host = host
        self.port = port
    
    def _send_request(self, data: Dict) -> Dict:
        """Send a request to the RAG service"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(SOCKET_TIMEOUT)
            sock.connect((self.host, self.port))
            
            # Send request
            request_json = json.dumps(data) + '\n'
            sock.send(request_json.encode('utf-8'))
            
            # Receive response
            response_data = b''
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response_data += chunk
                if b'\n' in response_data:
                    break
            
            response = json.loads(response_data.decode('utf-8').strip())
            return response
            
        except Exception as e:
            return {
                'status': 'error',
                'error': f'Connection error: {str(e)}'
            }
        finally:
            sock.close()
    
    def query(self, query: str, request_id: str = None) -> str:
        """Send a query to the RAG service"""
        if request_id is None:
            request_id = f"query_{int(time.time())}"
        
        request = {
            'command': 'query',
            'query': query,
            'request_id': request_id
        }
        
        response = self._send_request(request)
        
        if response.get('status') == 'success':
            return response.get('answer', 'No answer received')
        else:
            return f"❌ Error: {response.get('error', 'Unknown error')}"
    
    def get_status(self) -> Dict:
        """Get the status of the RAG service"""
        request = {
            'command': 'status',
            'request_id': f"status_{int(time.time())}"
        }
        
        response = self._send_request(request)
        return response
    
    def ping(self) -> bool:
        """Check if the RAG service is responsive"""
        request = {
            'command': 'ping',
            'request_id': f"ping_{int(time.time())}"
        }
        
        response = self._send_request(request)
        return response.get('status') == 'success'
    
    def shutdown(self) -> bool:
        """Shutdown the RAG service"""
        request = {
            'command': 'shutdown',
            'request_id': f"shutdown_{int(time.time())}"
        }
        
        response = self._send_request(request)
        return response.get('status') == 'success'

# Convenience functions for external use
def query_rag_system(query: str, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> str:
    """Query the RAG system via client"""
    client = RAGClient(host, port)
    return client.query(query)

def get_system_status(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> Dict:
    """Get system status via client"""
    client = RAGClient(host, port)
    return client.get_status()

def is_service_running(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> bool:
    """Check if RAG service is running"""
    client = RAGClient(host, port)
    return client.ping()

def run_service(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT):
    """Run the RAG service"""
    service = RAGService(host, port)
    
    # Handle graceful shutdown
    def signal_handler(signum, frame):
        logger.info("Received shutdown signal")
        service.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    service.start()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='RAG IoT Q&A Service')
    parser.add_argument('--mode', choices=['service', 'client', 'test'], default='service',
                      help='Run mode: service, client, or test')
    parser.add_argument('--host', default=DEFAULT_HOST, help='Host address')
    parser.add_argument('--port', type=int, default=DEFAULT_PORT, help='Port number')
    parser.add_argument('--query', type=str, help='Query for client mode')
    
    args = parser.parse_args()
    
    if args.mode == 'service':
        logger.info("Starting RAG service...")
        run_service(args.host, args.port)
        
    elif args.mode == 'client':
        if args.query:
            client = RAGClient(args.host, args.port)
            answer = client.query(args.query)
            print(f"Answer: {answer}")
        else:
            print("Please provide a query with --query")
            
    elif args.mode == 'test':
        # Test both service and client
        import subprocess
        import time
        
        print("🔍 Testing RAG service...")
        
        # Start service in background
        service_process = subprocess.Popen([
            sys.executable, __file__, '--mode', 'service', '--host', args.host, '--port', str(args.port)
        ])
        
        # Wait for service to start
        time.sleep(3)
        
        try:
            client = RAGClient(args.host, args.port)
            
            # Test ping
            if client.ping():
                print("✅ Service is responsive")
            else:
                print("❌ Service not responsive")
                
            # Test status
            status = client.get_status()
            print(f"📊 Service status: {status}")
            
            # Test query
            test_query = "What privacy implications does Amazon Echo have?"
            answer = client.query(test_query)
            print(f"❓ Query: {test_query}")
            print(f"💬 Answer: {answer}")
            
        finally:
            # Shutdown service
            try:
                client.shutdown()
            except:
                service_process.terminate()
            service_process.wait()