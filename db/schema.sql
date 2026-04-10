-- Enable the pgvector extension
CREATE EXTENSION IF NOT EXISTS vector;

-- Create a table to store network logs with vector embeddings
-- This assumes you want to store a vector representation of your log entries
--CREATE TABLE IF NOT EXISTS network_logs (
--    id SERIAL PRIMARY KEY,
--    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
--    src_ip INET,
--    dst_ip INET,
--    src_port INTEGER,
--    dst_port INTEGER,
--    protocol VARCHAR(10),
--    raw_log TEXT,
--    -- Assuming a standard embedding dimension, e.g., 1536 for OpenAI text-embedding-3-small
--    embedding vector(1536)
--);
--

-- Create an index for efficient vector similarity search
--CREATE INDEX IF NOT EXISTS network_logs_embedding_idx ON network_logs USING ivfflat (embedding vector_cosine_ops);

-- Create a table for metadata or processed insights
-- CREATE TABLE IF NOT EXISTS log_insights (
--     id SERIAL PRIMARY KEY,
--     log_id INTEGER REFERENCES network_logs(id) ON DELETE CASCADE,
--     insight_text TEXT,
--     created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
-- );
