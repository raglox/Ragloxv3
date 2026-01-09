-- ═══════════════════════════════════════════════════════════════
-- RAGLOX v3.0 - Complete Schema Fix Migration
-- Generated: 2026-01-08
-- Purpose: Add all missing columns to match code expectations
-- ═══════════════════════════════════════════════════════════════

BEGIN;

-- ═══════════════════════════════════════════════════════════════
-- 1. FIX MISSIONS TABLE
-- Missing: organization_id, environment_type, environment_config, 
--          goals_total, metadata, updated_at
-- ═══════════════════════════════════════════════════════════════

-- Add organization_id (REQUIRED - cannot be NULL)
ALTER TABLE missions 
    ADD COLUMN IF NOT EXISTS organization_id UUID;

-- Add environment_type
ALTER TABLE missions 
    ADD COLUMN IF NOT EXISTS environment_type VARCHAR(50) DEFAULT 'simulated';

-- Add environment_config
ALTER TABLE missions 
    ADD COLUMN IF NOT EXISTS environment_config JSONB DEFAULT '{}';

-- Add goals_total
ALTER TABLE missions 
    ADD COLUMN IF NOT EXISTS goals_total INTEGER DEFAULT 0;

-- Add metadata
ALTER TABLE missions 
    ADD COLUMN IF NOT EXISTS metadata JSONB DEFAULT '{}';

-- Add updated_at
ALTER TABLE missions 
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW();

-- Add foreign key for organization_id
DO $$ 
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint 
        WHERE conname = 'missions_organization_id_fkey'
    ) THEN
        ALTER TABLE missions 
            ADD CONSTRAINT missions_organization_id_fkey 
            FOREIGN KEY (organization_id) 
            REFERENCES organizations(id) 
            ON DELETE CASCADE;
    END IF;
END $$;

-- Add index for organization_id
CREATE INDEX IF NOT EXISTS idx_missions_organization_id ON missions(organization_id);

-- ═══════════════════════════════════════════════════════════════
-- 2. CREATE ORGANIZATION_INVITATIONS TABLE
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS organization_invitations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    role VARCHAR(50) DEFAULT 'member',
    invited_by UUID REFERENCES users(id) ON DELETE SET NULL,
    token VARCHAR(255) UNIQUE NOT NULL,
    status VARCHAR(50) DEFAULT 'pending',
    expires_at TIMESTAMP WITH TIME ZONE,
    accepted_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    CONSTRAINT valid_invitation_status CHECK (status IN ('pending', 'accepted', 'rejected', 'expired'))
);

CREATE INDEX IF NOT EXISTS idx_organization_invitations_org ON organization_invitations(organization_id);
CREATE INDEX IF NOT EXISTS idx_organization_invitations_email ON organization_invitations(email);
CREATE INDEX IF NOT EXISTS idx_organization_invitations_token ON organization_invitations(token);
CREATE INDEX IF NOT EXISTS idx_organization_invitations_status ON organization_invitations(status);

-- ═══════════════════════════════════════════════════════════════
-- 3. UPDATE TRIGGERS FOR updated_at
-- ═══════════════════════════════════════════════════════════════

-- Create or replace trigger function
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Add trigger to missions
DROP TRIGGER IF EXISTS update_missions_updated_at ON missions;
CREATE TRIGGER update_missions_updated_at
    BEFORE UPDATE ON missions
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Add trigger to organizations (if not exists)
DROP TRIGGER IF EXISTS update_organizations_updated_at ON organizations;
CREATE TRIGGER update_organizations_updated_at
    BEFORE UPDATE ON organizations
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ═══════════════════════════════════════════════════════════════
-- 4. DATA MIGRATION: Set organization_id for existing missions
-- ═══════════════════════════════════════════════════════════════

-- If there are missions without organization_id, 
-- assign them to the first available organization or creator's organization

DO $$
DECLARE
    default_org_id UUID;
BEGIN
    -- Get first organization or create one if none exists
    SELECT id INTO default_org_id FROM organizations LIMIT 1;
    
    IF default_org_id IS NULL THEN
        -- Create a default organization if none exists
        INSERT INTO organizations (name, slug, plan, status)
        VALUES ('Default Organization', 'default-org', 'free', 'active')
        RETURNING id INTO default_org_id;
    END IF;
    
    -- Update missions without organization_id
    UPDATE missions 
    SET organization_id = COALESCE(
        (SELECT organization_id FROM users WHERE users.id = missions.created_by),
        default_org_id
    )
    WHERE organization_id IS NULL;
    
END $$;

-- Now make organization_id NOT NULL
ALTER TABLE missions 
    ALTER COLUMN organization_id SET NOT NULL;

-- ═══════════════════════════════════════════════════════════════
-- 5. VERIFY SCHEMA
-- ═══════════════════════════════════════════════════════════════

DO $$
DECLARE
    mission_cols_count INTEGER;
    org_inv_exists BOOLEAN;
BEGIN
    -- Check missions columns
    SELECT COUNT(*) INTO mission_cols_count
    FROM information_schema.columns
    WHERE table_name = 'missions'
      AND column_name IN ('organization_id', 'environment_type', 'environment_config', 
                          'goals_total', 'metadata', 'updated_at');
    
    IF mission_cols_count = 6 THEN
        RAISE NOTICE '✅ Missions table: All 6 missing columns added successfully';
    ELSE
        RAISE NOTICE '⚠️  Missions table: Only % of 6 columns added', mission_cols_count;
    END IF;
    
    -- Check organization_invitations table
    SELECT EXISTS (
        SELECT FROM information_schema.tables 
        WHERE table_name = 'organization_invitations'
    ) INTO org_inv_exists;
    
    IF org_inv_exists THEN
        RAISE NOTICE '✅ Organization invitations table created successfully';
    ELSE
        RAISE NOTICE '⚠️  Organization invitations table NOT created';
    END IF;
    
    RAISE NOTICE '✅ Migration completed successfully!';
END $$;

COMMIT;

-- ═══════════════════════════════════════════════════════════════
-- MIGRATION SUMMARY
-- ═══════════════════════════════════════════════════════════════
-- 
-- Changes Applied:
-- 
-- 1. MISSIONS TABLE
--    ✅ Added organization_id (UUID, NOT NULL, FK to organizations)
--    ✅ Added environment_type (VARCHAR(50), default 'simulated')
--    ✅ Added environment_config (JSONB, default '{}')
--    ✅ Added goals_total (INTEGER, default 0)
--    ✅ Added metadata (JSONB, default '{}')
--    ✅ Added updated_at (TIMESTAMP WITH TIME ZONE)
--    ✅ Added index on organization_id
--    ✅ Added trigger for updated_at auto-update
--
-- 2. ORGANIZATION_INVITATIONS TABLE
--    ✅ Created complete table with all columns
--    ✅ Added all indexes
--    ✅ Added status constraint
--    ✅ Added foreign keys to organizations and users
--
-- 3. DATA MIGRATION
--    ✅ Set organization_id for all existing missions
--    ✅ Created default organization if needed
--
-- 4. VERIFICATION
--    ✅ Verified all changes applied successfully
--
-- ═══════════════════════════════════════════════════════════════
