import requests
from pathlib import Path
import logging
import pandas as pd
import numpy as np
import faiss
from sentence_transformers import SentenceTransformer
import requests
import os
from typing import List

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Configuration
HEADERS = {'User-Agent': 'Mozilla/5.0 (RAG-Research-Demo)'}
MAX_BYTES = 2_000_000  # ~2MB per file
MAX_WORKERS = 10  # Number of threads
DATA_DIR = Path('privacy_agent/rag_iot_data/device_database')
DATA_DIR.mkdir(parents=True, exist_ok=True)

MODEL_NAME = 'sentence-transformers/all-MiniLM-L6-v2'
EMBED_DIM = 384  # known dimension for the above model
TOP_K = 5


# Ollama Configuration for local LLM
class OllamaConfig:
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
        except:
            return False
    
    def get_available_models(self) -> List[str]:
        """Get list of available models from Ollama"""
        try:
            response = requests.get(f"{self.ollama_url}/api/tags", timeout=5)
            if response.status_code == 200:
                models = response.json().get('models', [])
                return [model['name'] for model in models]
        except:
            return []
        return []

# Initialize Ollama confiG
ollama_config = OllamaConfig()
OLLAMA_AVAILABLE = ollama_config.is_available()

def call_ollama(prompt: str, system_prompt: str = None) -> str:
    """Call Ollama API with proper error handling"""
    
    if not OLLAMA_AVAILABLE:
        return "❌ Ollama is not available. Please start Ollama and ensure the model is installed."
    
    for attempt in range(ollama_config.max_retries):
        try:
            if system_prompt:
                # Use chat API format
                url = f"{ollama_config.ollama_url}/api/chat"
                payload = {
                    "model": ollama_config.model_name,
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
                # Use generate API format
                url = f"{ollama_config.ollama_url}/api/generate"
                payload = {
                    "model": ollama_config.model_name,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": 0.2,
                        "top_p": 0.9,
                        "num_predict": 600
                    }
                }
            
            response = requests.post(url, json=payload, timeout=ollama_config.timeout)
            response.raise_for_status()
            
            result = response.json()
            
            if system_prompt:
                return result.get('message', {}).get('content', 'No response').strip()
            else:
                return result.get('response', 'No response').strip()
                
        except requests.exceptions.ConnectionError:
            if attempt == ollama_config.max_retries - 1:
                return f"❌ Could not connect to Ollama at {ollama_config.ollama_url}"
        except requests.exceptions.Timeout:
            if attempt == ollama_config.max_retries - 1:
                return "❌ Request timed out"
        except Exception as e:
            if attempt == ollama_config.max_retries - 1:
                return f"❌ Error: {str(e)}"
    
    return "❌ All retry attempts failed"



def load_artifacts():
    df = pd.read_parquet(DATA_DIR / 'corpus.parquet')
    index = faiss.read_index(str(DATA_DIR / 'index.faiss'))
    embeddings = np.load(DATA_DIR / 'embeddings.npy')
    return df, index, embeddings

def retrieve(query: str, k: int = TOP_K) -> pd.DataFrame:
    model = SentenceTransformer(MODEL_NAME)
    q_emb = model.encode([query], convert_to_numpy=True, normalize_embeddings=True)
    D, I = _index.search(q_emb, k)
    hits = _df.iloc[I[0]].copy()
    hits['score'] = D[0]
    return hits[['score','device','brand','kind','url','chunk_id','text']]


def synthesize_answer(query: str, hits: pd.DataFrame) -> str:
    context_blocks = []
    for _, row in hits.iterrows():
        cite = f"[{row['device']} | {row['kind']} | {row['url']}]"
        context_blocks.append(f"SOURCE: {cite}\n{row['text']}")
    context_text = '\n\n'.join(context_blocks)

    if OLLAMA_AVAILABLE:
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
            response = call_ollama(user_prompt, system_prompt)
            if response.startswith("❌"):
                return f"{response}\n\n📚 Top passages for reference:\n\n{context_text}"
            return response
        except Exception as e:
            return f"❌ Generation error: {e}\n\n📚 Top passages:\n\n{context_text}"
    else:
        # No Ollama: return the top passages as the 'answer'
        header = f"❌ Ollama not available at {ollama_config.ollama_url}. Showing top retrieved passages with citations.\n\n"
        return header + context_text

# Global variables to store loaded artifacts
_df = None
_index = None
_embeddings = None
_artifacts_loaded = False

def initialize_rag_system():
    """Load artifacts for retrieval - call this once at startup"""
    global _df, _index, _embeddings, _artifacts_loaded
    
    if _artifacts_loaded:
        logger.info("RAG system already initialized")
        return
    
    try:
        _df, _index, _embeddings = load_artifacts()
        _artifacts_loaded = True
        logger.info(f'✅ RAG artifacts loaded. Total chunks: {len(_df)}')
    except Exception as e:
        logger.error(f'❌ Failed to load RAG artifacts: {e}')
        raise

def query_rag_system(query: str) -> str:
    """
    Query the RAG system with a question about IoT devices.
    
    Args:
        query (str): The question to ask about IoT devices
        
    Returns:
        str: The synthesized answer with citations
    """
    global _df, _index, _embeddings, _artifacts_loaded
    
    # Ensure artifacts are loaded
    if not _artifacts_loaded:
        initialize_rag_system()
    
    try:
        # Use global variables instead of local ones
        # model = SentenceTransformer(MODEL_NAME)
        # q_emb = model.encode([query], convert_to_numpy=True, normalize_embeddings=True)
        # D, I = _index.search(q_emb, TOP_K)
        # hits = _df.iloc[I[0]].copy()
        # hits['score'] = D[0]
        # hits = hits[['score','device','brand','kind','url','chunk_id','text']]

        hits = retrieve(query, k=TOP_K)
        answer = synthesize_answer(query, hits)
        logger.info(f"RAG system query successful: {query}")
        return answer

    except Exception as e:
        logger.error(f'❌ Error querying RAG system: {e}')
        return f"❌ Error processing query: {str(e)}"

# Initialize the system once when the module is imported
try:
    initialize_rag_system()
except Exception as e:
    logger.warning(f"RAG system initialization failed: {e}")

# Example usage (can be removed in production)
if __name__ == "__main__":
    query = "What data does Ring Video Doorbell collect?"
    answer = query_rag_system(query)
    print('\n---\n')
    print(answer)