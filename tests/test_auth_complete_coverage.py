"""
Complete Coverage Tests for auth_routes.py
Target: Reach 85%+ coverage

Focus Areas:
- Lines 329-330: Invalid UUID handling
- Lines 338: User not found
- Lines 345: Inactive user
- Lines 583-594: Invalid invitation code + accept invitation
- Lines 614-626: Personal organization creation
- Lines 500-514: Background provisioning (already tested but ensure)
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4
from datetime import datetime
from fastapi import Request, HTTPException

# Import auth functions
import sys
sys.path.insert(0, "/root/RAGLOX_V3/webapp")

from src.api.auth_routes import (
    get_current_user,
    register,
    RegisterRequest,
)


class TestGetCurrentUserCoverage:
    """Cover lines 329-330, 338, 345"""
    
    @pytest.mark.asyncio
    async def test_get_current_user_invalid_uuid_in_token(self):
        """Test invalid UUID format in token payload - Line 329-330"""
        mock_request = MagicMock(spec=Request)
        mock_request.app.state.token_store = AsyncMock()
        
        mock_user_repo = AsyncMock()
        
        # Mock credentials with invalid UUID
        mock_credentials = MagicMock()
        mock_credentials.credentials = "valid_token"
        
        with patch("src.api.auth_routes.decode_token") as mock_decode:
            # Return payload with INVALID UUID format
            mock_decode.return_value = {
                "sub": "not-a-valid-uuid",  # Invalid UUID
                "org": "also-not-valid"
            }
            
            with patch("src.api.auth_routes.get_user_repo", return_value=mock_user_repo):
                # Should raise HTTPException 401 due to invalid UUID
                with pytest.raises(HTTPException) as exc_info:
                    await get_current_user(mock_request, mock_credentials)
                
                assert exc_info.value.status_code == 401
                assert "Invalid token data" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_get_current_user_not_found_in_db(self):
        """Test user not found in database - Line 338"""
        mock_request = MagicMock(spec=Request)
        mock_request.app.state.token_store = AsyncMock()
        
        mock_user_repo = AsyncMock()
        mock_user_repo.get_by_id = AsyncMock(return_value=None)  # User not found
        
        mock_credentials = MagicMock()
        mock_credentials.credentials = "valid_token"
        
        user_id = uuid4()
        org_id = uuid4()
        
        with patch("src.api.auth_routes.decode_token") as mock_decode:
            mock_decode.return_value = {
                "sub": str(user_id),
                "org": str(org_id)
            }
            
            with patch("src.api.auth_routes.get_user_repo", return_value=mock_user_repo):
                # Should raise HTTPException 401 - user not found
                with pytest.raises(HTTPException) as exc_info:
                    await get_current_user(mock_request, mock_credentials)
                
                assert exc_info.value.status_code == 401
                assert "User not found" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_get_current_user_inactive_account(self):
        """Test inactive user account - Line 345"""
        mock_request = MagicMock(spec=Request)
        mock_request.app.state.token_store = AsyncMock()
        
        # Mock User object (inactive)
        mock_user = MagicMock()
        mock_user.id = uuid4()
        mock_user.organization_id = uuid4()
        mock_user.email = "inactive@test.com"
        mock_user.username = "inactive_user"
        mock_user.full_name = "Inactive User"
        mock_user.role = "user"
        mock_user.is_active = False  # INACTIVE USER
        mock_user.is_superuser = False
        mock_user.is_org_owner = False
        mock_user.last_login_at = datetime.now()
        mock_user.created_at = datetime.now()
        mock_user.metadata = {}
        
        mock_user_repo = AsyncMock()
        mock_user_repo.get_by_id = AsyncMock(return_value=mock_user)
        
        mock_credentials = MagicMock()
        mock_credentials.credentials = "valid_token"
        
        with patch("src.api.auth_routes.decode_token") as mock_decode:
            mock_decode.return_value = {
                "sub": str(mock_user.id),
                "org": str(mock_user.organization_id)
            }
            
            with patch("src.api.auth_routes.get_user_repo", return_value=mock_user_repo):
                # Should raise HTTPException 403 - account suspended
                with pytest.raises(HTTPException) as exc_info:
                    await get_current_user(mock_request, mock_credentials)
                
                assert exc_info.value.status_code == 403
                assert "Account is suspended" in exc_info.value.detail


class TestRegisterInvitationCoverage:
    """Cover lines 583-594: Invalid invitation code"""
    
    @pytest.mark.asyncio
    async def test_register_with_invalid_invitation_code(self):
        """Test registration with invalid invitation code - Lines 583-594"""
        mock_request = MagicMock(spec=Request)
        mock_request.app.state.token_store = AsyncMock()
        
        mock_user_repo = AsyncMock()
        # Must return None for both get_by_email AND get_by_email_global
        mock_user_repo.get_by_email = AsyncMock(return_value=None)
        mock_user_repo.get_by_email_global = AsyncMock(return_value=None)
        
        mock_org_repo = AsyncMock()
        # Return None = invitation not found
        mock_org_repo.get_pending_invitation_by_code = AsyncMock(return_value=None)
        
        mock_background_tasks = MagicMock()
        
        data = RegisterRequest(
            email="newuser@test.com",
            password="SecurePass123!",
            full_name="New User",
            invite_code="INVALID_CODE"  # Invalid invitation code
        )
        
        with patch("src.api.auth_routes.get_user_repo", return_value=mock_user_repo):
            with patch("src.api.auth_routes.get_org_repo", return_value=mock_org_repo):
                with patch("src.api.auth_routes.create_access_token", return_value=("token123", 86400)):  # Return TUPLE
                    # Should raise HTTPException 400
                    with pytest.raises(HTTPException) as exc_info:
                        await register(mock_request, data, mock_background_tasks)
                    
                    assert exc_info.value.status_code == 400
                    assert "Invalid or expired invitation code" in exc_info.value.detail


class TestRegisterPersonalOrgCoverage:
    """Cover lines 614-626: Personal organization creation"""
    
    @pytest.mark.asyncio
    async def test_register_creates_personal_organization(self):
        """Test registration with personal organization - Lines 614-626"""
        mock_request = MagicMock(spec=Request)
        mock_request.app.state.token_store = AsyncMock()
        
        mock_user_repo = AsyncMock()
        # Both email checks must return None
        mock_user_repo.get_by_email = AsyncMock(return_value=None)
        mock_user_repo.get_by_email_global = AsyncMock(return_value=None)
        
        # Mock created user with ALL required fields
        user_id = uuid4()
        mock_user = MagicMock()
        mock_user.id = user_id
        mock_user.email = "personal@test.com"
        mock_user.username = "john_doe"
        mock_user.full_name = "John Doe"
        mock_user.role = "user"
        mock_user.organization_id = uuid4()
        mock_user.is_active = True
        mock_user.is_superuser = False
        mock_user.is_org_owner = True
        mock_user.created_at = datetime.now()
        mock_user.last_login_at = None
        mock_user.metadata = {"vm_status": "not_created", "vm_ip": None}
        mock_user_repo.create = AsyncMock(return_value=mock_user)
        
        # Mock personal org creation
        org_id = uuid4()
        mock_org = MagicMock()
        mock_org.id = org_id
        mock_org.name = "John Doe's Workspace"
        
        mock_org_repo = AsyncMock()
        mock_org_repo.create = AsyncMock(return_value=mock_org)
        
        mock_background_tasks = MagicMock()
        
        # Register WITHOUT invite_code and WITHOUT organization_name
        # Should trigger personal org creation (lines 614-626)
        data = RegisterRequest(
            email="personal@test.com",
            password="SecurePass123!",
            full_name="John Doe"
            # NO invite_code, NO organization_name
        )
        
        with patch("src.api.auth_routes.get_user_repo", return_value=mock_user_repo):
            with patch("src.api.auth_routes.get_org_repo", return_value=mock_org_repo):
                with patch("src.api.auth_routes.create_access_token", return_value=("token123", 86400)):  # Return TUPLE
                    with patch("src.api.auth_routes.get_token_store_from_request") as mock_store:
                        mock_token_store = AsyncMock()
                        mock_store.return_value = mock_token_store
                        
                        result = await register(mock_request, data, mock_background_tasks)
                        
                        # Verify personal organization was created
                        assert mock_org_repo.create.called
                        org_call_args = mock_org_repo.create.call_args[0][0]
                        assert "Workspace" in org_call_args.name
                        assert "personal-" in org_call_args.slug
                        assert result.access_token == "token123"  # Result is TokenResponse object


class TestRegisterNewOrgCoverage:
    """Ensure coverage of lines 596-610: New organization creation"""
    
    @pytest.mark.asyncio
    async def test_register_creates_new_organization(self):
        """Test registration with new organization name - Lines 596-610"""
        mock_request = MagicMock(spec=Request)
        mock_request.app.state.token_store = AsyncMock()
        
        mock_user_repo = AsyncMock()
        # Both email checks must return None
        mock_user_repo.get_by_email = AsyncMock(return_value=None)
        mock_user_repo.get_by_email_global = AsyncMock(return_value=None)
        
        user_id = uuid4()
        org_id = uuid4()
        
        # Mock created user with ALL required fields
        mock_user = MagicMock()
        mock_user.id = user_id
        mock_user.email = "neworg@test.com"
        mock_user.username = "org_admin"
        mock_user.full_name = "Org Admin"
        mock_user.role = "user"
        mock_user.organization_id = org_id
        mock_user.is_active = True
        mock_user.is_superuser = False
        mock_user.is_org_owner = True
        mock_user.created_at = datetime.now()
        mock_user.last_login_at = None
        mock_user.metadata = {"vm_status": "not_created", "vm_ip": None}
        mock_user_repo.create = AsyncMock(return_value=mock_user)
        
        mock_org = MagicMock()
        mock_org.id = org_id
        mock_org.name = "New Company Inc"
        
        mock_org_repo = AsyncMock()
        mock_org_repo.create = AsyncMock(return_value=mock_org)
        
        mock_background_tasks = MagicMock()
        
        data = RegisterRequest(
            email="neworg@test.com",
            password="SecurePass123!",
            full_name="Org Admin",
            organization_name="New Company Inc"  # NEW ORG
        )
        
        with patch("src.api.auth_routes.get_user_repo", return_value=mock_user_repo):
            with patch("src.api.auth_routes.get_org_repo", return_value=mock_org_repo):
                with patch("src.api.auth_routes.create_access_token", return_value=("token123", 86400)):  # Return TUPLE
                    with patch("src.api.auth_routes.get_token_store_from_request") as mock_store:
                        mock_token_store = AsyncMock()
                        mock_store.return_value = mock_token_store
                        
                        result = await register(mock_request, data, mock_background_tasks)
                        
                        # Verify new organization was created
                        assert mock_org_repo.create.called
                        org_call_args = mock_org_repo.create.call_args[0][0]
                        assert org_call_args.name == "New Company Inc"
                        assert org_call_args.slug == "new-company-inc"
                        assert result.access_token == "token123"  # Result is TokenResponse object
