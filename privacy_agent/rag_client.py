"""
Simple client interface for RAG IoT Q&A Service
"""

from .rag_iot_service import RAGClient, query_rag_system, get_system_status, is_service_running

# Export the main functions for easy import
__all__ = ['RAGClient', 'query_rag_system', 'get_system_status', 'is_service_running']

# Default client instance
_default_client = None

def get_client(host='localhost', port=8899):
    """Get a RAG client instance"""
    global _default_client
    if _default_client is None:
        _default_client = RAGClient(host, port)
    return _default_client

def query(question: str) -> str:
    """Simple query function using default client"""
    return query_rag_system(question)

def status() -> dict:
    """Get service status using default client"""
    return get_system_status()

def ping() -> bool:
    """Check if service is running using default client"""
    return is_service_running()