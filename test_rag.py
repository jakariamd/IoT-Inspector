from privacy_agent.rag_iot_service import RAGClient

# Create client
client = RAGClient('localhost', 8899)

# Query
answer = client.query("What are the privacy options do Google Home Mini have?")
print(answer)

# Get status
status = client.get_status()
print(status)