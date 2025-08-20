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

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Configuration
HEADERS = {'User-Agent': 'Mozilla/5.0 (RAG-Research-Demo)'}
MODEL_NAME = 'sentence-transformers/all-MiniLM-L6-v2'
EMBED_DIM = 384
TOP_K = 5

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
        self.timeout = int(os.getenv('LLM_TIMEOUT', '30'))
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

class RAGSystem:
    """IoT Device Privacy RAG System with isolated imports"""
    
    def __init__(self):
        self.ollama_config = OllamaConfig()
        self.ollama_available = False
        self.df: Optional[pd.DataFrame] = None
        self.index: Optional[Any] = None
        self.embeddings: Optional[np.ndarray] = None
        self.artifacts_loaded = False
        self.lock = threading.Lock()
        self.sentence_transformer: Optional[Any] = None
        self._ollama_checked = False
        self._models_loaded = False
    
    def _check_ollama_availability(self):
        """Check Ollama availability only when needed"""
        if not self._ollama_checked:
            self.ollama_available = self.ollama_config.is_available()
            self._ollama_checked = True
    
    def _load_ml_models(self) -> bool:
        """Load ML models only when first needed"""
        if self._models_loaded:
            return True
        
        try:
            # Load SentenceTransformer
            SentenceTransformer = _get_sentence_transformer_class()
            if SentenceTransformer is None:
                raise ImportError("SentenceTransformer not available")
            
            self.sentence_transformer = SentenceTransformer(MODEL_NAME)
            self._models_loaded = True
            logger.info("✅ ML models loaded successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load ML models: {e}")
            return False
    
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
    
    def initialize(self, load_models: bool = False) -> bool:
        """Initialize the RAG system"""
        with self.lock:
            if self.artifacts_loaded:
                logger.info("RAG system already initialized")
                return True
            
            try:
                # Load artifacts first
                if not self._load_artifacts():
                    return False
                
                # Optionally load ML models
                if load_models:
                    if not self._load_ml_models():
                        logger.warning("Failed to load ML models, will try on first query")
                
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
        """Retrieve relevant chunks for a query"""
        if not self.artifacts_loaded:
            raise RuntimeError("RAG system not initialized")
        
        # Load ML models only when needed for the first time
        if not self._models_loaded:
            if not self._load_ml_models():
                raise RuntimeError("Failed to load ML models for query processing")
        
        # Encode query
        q_emb = self.sentence_transformer.encode([query], convert_to_numpy=True, normalize_embeddings=True)
        
        # Search index
        D, I = self.index.search(q_emb, k)
        
        # Get results
        hits = self.df.iloc[I[0]].copy()
        hits['score'] = D[0]
        return hits[['score', 'device', 'brand', 'kind', 'url', 'chunk_id', 'text']]
    
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
        Query the RAG system with a question about IoT devices.
        
        Args:
            query (str): The question to ask about IoT devices
            
        Returns:
            str: The synthesized answer with citations
        """
        if not self.artifacts_loaded:
            if not self.initialize():
                return "❌ Failed to initialize RAG system"
        
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
        return {
            "artifacts_loaded": self.artifacts_loaded,
            "models_loaded": self._models_loaded,
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

# Global instance management
_rag_system = None
_init_lock = threading.Lock()

def get_rag_system() -> RAGSystem:
    """Get or create the global RAG system instance"""
    global _rag_system
    if _rag_system is None:
        with _init_lock:
            if _rag_system is None:
                _rag_system = RAGSystem()
    return _rag_system

# Public API functions
def query_rag_system(query: str) -> str:
    """
    Query the RAG system with a question about IoT devices.
    
    Args:
        query (str): The question to ask about IoT devices
        
    Returns:
        str: The synthesized answer with citations
    """
    try:
        return get_rag_system().query(query)
    except Exception as e:
        logger.error(f"Error in query_rag_system: {e}")
        return f"❌ System error: {str(e)}"

def initialize_rag_system(load_models: bool = False) -> bool:
    """Initialize the RAG system"""
    try:
        return get_rag_system().initialize(load_models=load_models)
    except Exception as e:
        logger.error(f"Error initializing RAG system: {e}")
        return False

def get_system_status() -> Dict:
    """Get the current status of the RAG system"""
    try:
        return get_rag_system().get_status()
    except Exception as e:
        logger.error(f"Error getting system status: {e}")
        return {"error": str(e)}

def check_dependencies() -> Dict[str, bool]:
    """Check if required dependencies are available"""
    deps = {
        'pandas': True,
        'numpy': True,
        'requests': True,
    }
    
    # Check optional ML dependencies without importing
    try:
        importlib.util.find_spec('faiss')
        deps['faiss'] = True
    except (ImportError, AttributeError):
        deps['faiss'] = False
    
    try:
        importlib.util.find_spec('sentence_transformers')
        deps['sentence_transformers'] = True
    except (ImportError, AttributeError):
        deps['sentence_transformers'] = False
    
    return deps

def check_artifacts() -> Dict[str, bool]:
    """Check if RAG artifacts exist"""
    artifacts = {}
    for filename in ['corpus.parquet', 'index.faiss', 'embeddings.npy']:
        artifacts[filename] = (DATA_DIR / filename).exists()
    return artifacts

# Minimal safe initialization - just check if files exist
def _safe_startup_check():
    """Safe startup check without loading any ML libraries"""
    try:
        artifacts = check_artifacts()
        if all(artifacts.values()):
            logger.info("✅ All RAG artifacts found - system ready")
        else:
            missing = [k for k, v in artifacts.items() if not v]
            logger.info(f"⚠️  Missing RAG artifacts: {missing}")
    except Exception as e:
        logger.info(f"Startup check failed: {e}")

# Run safe startup check
_safe_startup_check()

if __name__ == "__main__":
    # Example usage
    print("🔍 Checking dependencies...")
    deps = check_dependencies()
    print(f"Dependencies: {deps}")
    
    print("\n🔍 Checking artifacts...")
    artifacts = check_artifacts()
    print(f"Artifacts: {artifacts}")
    
    if all(deps[k] for k in ['faiss', 'sentence_transformers']) and all(artifacts.values()):
        print("\n🚀 Testing RAG system...")
        rag = get_rag_system()
        if rag.initialize(load_models=True):
            query = "What is the privacy implication of this Amazon Echo Dot device?"
            answer = query_rag_system(query)
            print('\n---\n')
            print(answer)
        else:
            print("❌ Failed to initialize RAG system")
    else:
        missing_deps = [k for k, v in deps.items() if not v]
        missing_artifacts = [k for k, v in artifacts.items() if not v]
        if missing_deps:
            print(f"❌ Missing dependencies: {missing_deps}")
        if missing_artifacts:
            print(f"❌ Missing artifacts: {missing_artifacts}")