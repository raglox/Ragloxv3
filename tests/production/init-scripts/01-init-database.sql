-- PostgreSQL Initialization Script for RAGLOX Production Testing
-- This script runs automatically when the database is first created

-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- Create test user (if not exists, though it's created by env var)
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_user WHERE usename = 'raglox_test') THEN
        CREATE USER raglox_test WITH PASSWORD 'test_password_secure_123';
    END IF;
END
$$;

-- Grant permissions
GRANT ALL PRIVILEGES ON DATABASE raglox_test_production TO raglox_test;

-- Create schema if needed
CREATE SCHEMA IF NOT EXISTS public;
GRANT ALL ON SCHEMA public TO raglox_test;

-- Log initialization
DO $$
BEGIN
    RAISE NOTICE 'RAGLOX Test Database initialized successfully';
    RAISE NOTICE 'Database: raglox_test_production';
    RAISE NOTICE 'User: raglox_test';
    RAISE NOTICE 'Ready for production testing';
END
$$;
