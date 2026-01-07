# خطة الاختبار الشاملة - RAGLOX v3.0
## رفع التغطية من 34% إلى 85%+

---

## 📊 الإحصائيات الدقيقة من تقرير التغطية

### 1. `src/api/auth_routes.py`
```
إجمالي الأسطر: 418
الأسطر المغطاة: 217 (52%)
الأسطر المفقودة: 201 (48%)
الفروع الكلية: 100
الفروع المفقودة: 79 (79%)
```

### 2. `src/controller/mission.py`
```
إجمالي الأسطر: 756
الأسطر المغطاة: 219 (29%)
الأسطر المفقودة: 537 (71%)
الفروع الكلية: 240
الفروع المفقودة: 188 (78%)
```

### 3. `src/core/database/user_repository.py`
```
إجمالي الأسطر: 135
الأسطر المغطاة: 76 (56%)
الأسطر المفقودة: 59 (44%)
```

**إجمالي:**
- الأسطر الكلية: 1309
- المغطاة: 512 (39%)
- المفقودة: 797 (61%)
- **مطلوب لـ 85%:** 1113 سطر (601 سطر إضافي)

---

## 🎯 استراتيجية الاختبار

### المرحلة 1: الأولوية العالية (Critical) - 60% من الجهد
**الهدف:** رفع التغطية إلى 70%

#### 1.1 Authentication Routes (أسبوع 1)
**الملف:** `tests/test_auth_routes_extended.py`

##### اختبارات تسجيل الدخول (Login)
```python
class TestLogin:
    """Test login functionality"""
    
    async def test_login_success(self):
        """Test successful login"""
        # Setup: Create user with known password
        # Action: POST /auth/login
        # Assert: 200, token returned, user data correct
        
    async def test_login_wrong_password(self):
        """Test login with wrong password"""
        # Assert: 401, login_attempts incremented
        
    async def test_login_account_locked(self):
        """Test login with locked account"""
        # Setup: Lock account (5 failed attempts)
        # Assert: 423, locked message
        
    async def test_login_account_suspended(self):
        """Test login with suspended account"""
        # Setup: Suspend user
        # Assert: 403, suspended message
        
    async def test_login_remember_me(self):
        """Test login with remember_me=True"""
        # Assert: Token expires in 7 days (168 hours)
        
    async def test_login_increments_failed_attempts(self):
        """Test failed login increments counter"""
        # Action: 3 failed logins
        # Assert: login_attempts = 3
        
    async def test_login_locks_after_5_attempts(self):
        """Test account locks after 5 failed attempts"""
        # Action: 5 failed logins
        # Assert: locked_until is set, 423 status
```

##### اختبارات تسجيل الخروج (Logout)
```python
class TestLogout:
    """Test logout functionality"""
    
    async def test_logout_success(self):
        """Test successful logout"""
        # Setup: Login first
        # Action: POST /auth/logout
        # Assert: 200, token revoked
        
    async def test_logout_token_revoked(self):
        """Test token is actually revoked"""
        # Action: Logout, then try to use token
        # Assert: 401 on subsequent request
```

##### اختبارات إدارة الملف الشخصي
```python
class TestProfile:
    """Test profile management"""
    
    async def test_get_current_user_info(self):
        """Test GET /auth/me"""
        # Assert: User data returned correctly
        
    async def test_update_profile_full_name(self):
        """Test PUT /auth/me"""
        # Action: Update full_name
        # Assert: 200, name updated
        
    async def test_update_profile_empty_data(self):
        """Test update with no changes"""
        # Assert: 200, no changes made
```

##### اختبارات تغيير كلمة المرور
```python
class TestPasswordChange:
    """Test password change"""
    
    async def test_change_password_success(self):
        """Test successful password change"""
        # Action: POST /auth/change-password
        # Assert: 200, password updated, all tokens revoked
        
    async def test_change_password_wrong_current(self):
        """Test with wrong current password"""
        # Assert: 401
        
    async def test_change_password_weak_new(self):
        """Test with weak new password"""
        # Assert: 422, validation error
        
    async def test_change_password_revokes_all_tokens(self):
        """Test all tokens are revoked"""
        # Setup: Create 3 tokens
        # Action: Change password
        # Assert: All 3 tokens invalid
```

##### اختبارات إدارة المستخدمين (Admin)
```python
class TestAdminRoutes:
    """Test admin user management"""
    
    async def test_list_organization_users(self):
        """Test GET /auth/admin/users"""
        # Setup: Create 5 users in org
        # Assert: Returns all 5 users
        
    async def test_update_user_status_suspend(self):
        """Test suspending a user"""
        # Action: PUT /auth/admin/users/{id}/status
        # Assert: User suspended, tokens revoked
        
    async def test_update_user_status_cannot_suspend_self(self):
        """Test admin cannot suspend themselves"""
        # Assert: 400
        
    async def test_update_user_role(self):
        """Test changing user role"""
        # Action: PUT /auth/admin/users/{id}/role
        # Assert: Role updated
        
    async def test_update_user_role_invalid(self):
        """Test invalid role"""
        # Assert: 400
```

##### اختبارات الدعوات (Invitations)
```python
class TestInvitations:
    """Test organization invitations"""
    
    async def test_invite_user_success(self):
        """Test POST /auth/organization/invite"""
        # Assert: Invitation created, code generated
        
    async def test_invite_existing_user(self):
        """Test inviting existing user"""
        # Assert: 409
        
    async def test_register_with_invite_code(self):
        """Test registration with invite code"""
        # Setup: Create invitation
        # Action: Register with code
        # Assert: User joins organization
```

##### اختبارات JWT
```python
class TestJWT:
    """Test JWT token operations"""
    
    async def test_create_access_token(self):
        """Test token creation"""
        # Assert: Token created, stored in Redis
        
    async def test_decode_token_valid(self):
        """Test decoding valid token"""
        # Assert: Payload extracted correctly
        
    async def test_decode_token_expired(self):
        """Test decoding expired token"""
        # Assert: Returns None
        
    async def test_decode_token_invalid(self):
        """Test decoding invalid token"""
        # Assert: Returns None
        
    async def test_get_current_user_valid_token(self):
        """Test get_current_user with valid token"""
        # Assert: User data returned
        
    async def test_get_current_user_no_token(self):
        """Test get_current_user without token"""
        # Assert: 401
        
    async def test_get_current_user_revoked_token(self):
        """Test with revoked token"""
        # Assert: 401
```

**تقدير الاختبارات:** 35 اختبار  
**التغطية المتوقعة:** +30% (من 52% إلى 82%)

---

#### 1.2 Mission Controller (أسبوع 2-3)
**الملف:** `tests/test_mission_controller_extended.py`

##### اختبارات دورة حياة المهمة
```python
class TestMissionLifecycle:
    """Test mission lifecycle operations"""
    
    async def test_create_mission_with_org(self):
        """Test creating mission with organization_id"""
        # Assert: Mission created, org_id set
        
    async def test_create_mission_multiple_goals(self):
        """Test mission with multiple goals"""
        # Assert: All goals initialized as PENDING
        
    async def test_start_mission_initializes_managers(self):
        """Test start_mission starts SessionManager and StatsManager"""
        # Assert: Both managers started
        
    async def test_start_mission_creates_initial_task(self):
        """Test initial scan task created"""
        # Assert: NETWORK_SCAN task exists
        
    async def test_start_mission_wrong_status(self):
        """Test starting mission in wrong status"""
        # Setup: Mission already running
        # Assert: Returns False
        
    async def test_pause_mission_sends_control_command(self):
        """Test pause sends control command"""
        # Assert: Control command published
        
    async def test_resume_mission_from_paused(self):
        """Test resuming paused mission"""
        # Assert: Status changes to RUNNING
        
    async def test_stop_mission_cleans_up(self):
        """Test stop_mission cleanup"""
        # Assert: Specialists stopped, managers stopped
```

##### اختبارات الموافقات (HITL)
```python
class TestApprovals:
    """Test Human-in-the-Loop approvals"""
    
    async def test_request_approval_creates_action(self):
        """Test approval request creation"""
        # Assert: Action stored in Redis and memory
        
    async def test_request_approval_pauses_mission(self):
        """Test mission pauses while waiting"""
        # Assert: Status = WAITING_FOR_APPROVAL
        
    async def test_approve_action_resumes_mission(self):
        """Test approval resumes mission"""
        # Assert: Status = RUNNING, task re-queued
        
    async def test_approve_action_with_audit_info(self):
        """Test approval with audit logging"""
        # Assert: Audit info saved to Redis
        
    async def test_reject_action_requests_alternative(self):
        """Test rejection triggers analysis"""
        # Assert: Analysis request published
        
    async def test_reject_action_with_reason(self):
        """Test rejection with reason"""
        # Assert: Reason stored
        
    async def test_get_pending_approvals_from_redis(self):
        """Test retrieving approvals from Redis"""
        # Setup: Create approval, restart controller
        # Assert: Approval restored from Redis
        
    async def test_approval_expires(self):
        """Test approval expiration"""
        # Setup: Create approval with short expiry
        # Assert: Approval marked as expired
```

##### اختبارات المراقبة والإحصائيات
```python
class TestMonitoring:
    """Test mission monitoring"""
    
    async def test_monitor_loop_checks_goals(self):
        """Test monitor checks goal completion"""
        # Setup: Achieve all goals
        # Assert: Mission stops automatically
        
    async def test_monitor_creates_exploit_tasks(self):
        """Test monitor creates tasks for critical vulns"""
        # Setup: Add critical vulnerability
        # Assert: EXPLOIT task created
        
    async def test_watchdog_detects_zombie_tasks(self):
        """Test watchdog finds stale tasks"""
        # Setup: Create task, mark as RUNNING, wait 6 minutes
        # Assert: Task re-queued
        
    async def test_watchdog_marks_failed_after_retries(self):
        """Test task marked FAILED after max retries"""
        # Setup: Task with 3 retries
        # Assert: Task marked FAILED
```

##### اختبارات الدردشة (Chat)
```python
class TestChat:
    """Test chat functionality"""
    
    async def test_send_chat_message_stores_in_redis(self):
        """Test message persistence"""
        # Assert: Message saved to Redis
        
    async def test_send_chat_message_generates_response(self):
        """Test AI response generation"""
        # Assert: System response created
        
    async def test_chat_command_status(self):
        """Test 'status' command"""
        # Assert: Returns mission status
        
    async def test_chat_command_pause(self):
        """Test 'pause' command"""
        # Assert: Mission paused
        
    async def test_chat_command_help(self):
        """Test 'help' command"""
        # Assert: Returns help text
        
    async def test_get_chat_history_from_redis(self):
        """Test retrieving chat history"""
        # Setup: Send 10 messages
        # Assert: All 10 retrieved
```

##### اختبارات تنفيذ الأوامر (Shell)
```python
class TestShellExecution:
    """Test shell command execution"""
    
    async def test_execute_command_via_ssh(self):
        """Test real SSH execution"""
        # Setup: Mock SSH environment
        # Assert: Command executed via SSH
        
    async def test_execute_command_simulation_mode(self):
        """Test simulation fallback"""
        # Setup: No environment
        # Assert: Simulation output returned
        
    async def test_execute_command_broadcasts_output(self):
        """Test WebSocket broadcast"""
        # Assert: Output broadcast via WebSocket
```

**تقدير الاختبارات:** 45 اختبار  
**التغطية المتوقعة:** +40% (من 29% إلى 69%)

---

#### 1.3 User Repository (أسبوع 4)
**الملف:** `tests/test_user_repository_extended.py`

##### اختبارات CRUD الأساسية
```python
class TestUserCRUD:
    """Test basic CRUD operations"""
    
    async def test_create_user(self):
        """Test user creation"""
        # Assert: User created in PostgreSQL
        
    async def test_get_by_id(self):
        """Test get user by ID"""
        # Assert: User retrieved correctly
        
    async def test_get_by_email(self):
        """Test get user by email"""
        # Assert: User found
        
    async def test_get_by_email_global(self):
        """Test global email search"""
        # Assert: User found across orgs
        
    async def test_get_by_username(self):
        """Test get by username"""
        # Assert: User found
        
    async def test_update_user(self):
        """Test user update"""
        # Assert: Fields updated
        
    async def test_delete_user(self):
        """Test user deletion"""
        # Assert: User deleted
```

##### اختبارات الأمان
```python
class TestSecurity:
    """Test security features"""
    
    async def test_record_login_success(self):
        """Test successful login recording"""
        # Assert: last_login_at updated, attempts reset
        
    async def test_record_failed_login(self):
        """Test failed login recording"""
        # Assert: login_attempts incremented
        
    async def test