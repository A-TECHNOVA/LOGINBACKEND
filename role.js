const express = require('express');
const { body, param, query } = require('express-validator');
const roleController = require('../controllers/roleController');
const authMiddleware = require('../middleware/authMiddleware');

const router = express.Router();

// Validation middleware
const assignRoleValidation = [
    body('userId')
        .notEmpty()
        .withMessage('User ID is required')
        .isMongoId()
        .withMessage('Invalid user ID format'),
    
    body('newRole')
        .isIn(['student', 'warden', 'dc'])
        .withMessage('Invalid role specified')
];

const roleNameValidation = [
    param('roleName')
        .isIn(['student', 'warden', 'dc'])
        .withMessage('Invalid role name')
];

const permissionValidation = [
    param('permission')
        .matches(/^can[A-Z][a-zA-Z]+$/)
        .withMessage('Invalid permission format')
];

const updatePermissionsValidation = [
    body('permissions')
        .isObject()
        .withMessage('Permissions must be an object'),
    
    body('permissions.*')
        .isBoolean()
        .withMessage('Permission values must be boolean')
];

const queryValidation = [
    query('page')
        .optional()
        .isInt({ min: 1 })
        .withMessage('Page must be a positive integer'),
    
    query('limit')
        .optional()
        .isInt({ min: 1, max: 100 })
        .withMessage('Limit must be between 1 and 100')
];

// Routes

/**
 * @route   GET /api/role
 * @desc    Get all available roles
 * @access  Private
 */
router.get('/', [
    authMiddleware.verifyToken
], roleController.getRoles);

/**
 * @route   GET /api/role/:roleName
 * @desc    Get specific role details
 * @access  Private
 */
router.get('/:roleName', [
    authMiddleware.verifyToken,
    ...roleNameValidation
], roleController.getRole);

/**
 * @route   GET /api/role/:roleName/users
 * @desc    Get users by role
 * @access  Private - Warden/DC only
 */
router.get('/:roleName/users', [
    authMiddleware.verifyToken,
    authMiddleware.authorize('warden', 'dc'),
    authMiddleware.checkPermission('canViewUsers'),
    ...roleNameValidation,
    ...queryValidation
], roleController.getUsersByRole);

/**
 * @route   POST /api/role/assign
 * @desc    Assign role to user
 * @access  Private - DC only
 */
router.post('/assign', [
    authMiddleware.verifyToken,
    authMiddleware.authorize('dc'),
    authMiddleware.sensitiveOperationLimit,
    ...assignRoleValidation
], roleController.assignRole);

/**
 * @route   GET /api/role/check/:permission
 * @desc    Check if current user has specific permission
 * @access  Private
 */
router.get('/check/:permission', [
    authMiddleware.verifyToken,
    ...permissionValidation
], roleController.checkPermission);

/**
 * @route   GET /api/role/stats/overview
 * @desc    Get role statistics
 * @access  Private - DC only
 */
router.get('/stats/overview', [
    authMiddleware.verifyToken,
    authMiddleware.authorize('dc'),
    authMiddleware.checkPermission('canGenerateReports')
], roleController.getRoleStats);

/**
 * @route   GET /api/role/permissions/matrix
 * @desc    Get permission matrix for all roles
 * @access  Private - DC only
 */
router.get('/permissions/matrix', [
    authMiddleware.verifyToken,
    authMiddleware.authorize('dc'),
    authMiddleware.checkPermission('canManageSystem')
], roleController.getPermissionMatrix);

/**
 * @route   PUT /api/role/:roleName/permissions
 * @desc    Update role permissions
 * @access  Private - DC only
 */
router.put('/:roleName/permissions', [
    authMiddleware.verifyToken,
    authMiddleware.authorize('dc'),
    authMiddleware.checkPermission('canManageSystem'),
    authMiddleware.sensitiveOperationLimit,
    ...roleNameValidation,
    ...updatePermissionsValidation
], roleController.updateRolePermissions);

/**
 * @route   POST /api/role/initialize
 * @desc    Initialize default roles (setup only)
 * @access  Private - DC only
 */
router.post('/initialize', [
    authMiddleware.verifyToken,
    authMiddleware.authorize('dc')
], roleController.initializeRoles);

/**
 * @route   GET /api/role/permissions/list
 * @desc    Get list of all available permissions
 * @access  Private - DC only
 */
router.get('/permissions/list', [
    authMiddleware.verifyToken,
    authMiddleware.authorize('dc')
], async (req, res) => {
    try {
        // Define all available permissions in the system
        const permissions = {
            // Dashboard access
            canViewDashboard: 'View dashboard and basic system information',
            
            // User management
            canViewUsers: 'View user profiles and information',
            canCreateUsers: 'Create new user accounts',
            canEditUsers: 'Edit existing user profiles',
            canDeleteUsers: 'Deactivate or delete user accounts',
            
            // Attendance management
            canViewAttendance: 'View attendance records',
            canMarkAttendance: 'Mark attendance for users',
            canEditAttendance: 'Edit existing attendance records',
            canGenerateAttendanceReports: 'Generate attendance reports',
            
            // Room management
            canViewRooms: 'View room information and assignments',
            canManageRooms: 'Manage room assignments and details',
            
            // Complaint management
            canViewComplaints: 'View complaints and issues',
            canCreateComplaints: 'Create new complaints',
            canResolveComplaints: 'Resolve and manage complaints',
            
            // Notice management
            canViewNotices: 'View system notices and announcements',
            canCreateNotices: 'Create new notices',
            canEditNotices: 'Edit existing notices',
            canDeleteNotices: 'Delete notices',
            
            // Fee management
            canViewFees: 'View fee information and payment status',
            canManageFees: 'Manage fees and payment records',
            
            // Reports
            canGenerateReports: 'Generate various system reports',
            
            // System administration
            canManageSystem: 'Manage system settings and configuration',
            canViewLogs: 'View system logs and audit trails'
        };

        res.json({
            success: true,
            data: {
                permissions,
                categories: {
                    dashboard: ['canViewDashboard'],
                    userManagement: ['canViewUsers', 'canCreateUsers', 'canEditUsers', 'canDeleteUsers'],
                    attendance: ['canViewAttendance', 'canMarkAttendance', 'canEditAttendance', 'canGenerateAttendanceReports'],
                    roomManagement: ['canViewRooms', 'canManageRooms'],
                    complaints: ['canViewComplaints', 'canCreateComplaints', 'canResolveComplaints'],
                    notices: ['canViewNotices', 'canCreateNotices', 'canEditNotices', 'canDeleteNotices'],
                    fees: ['canViewFees', 'canManageFees'],
                    reports: ['canGenerateReports'],
                    system: ['canManageSystem', 'canViewLogs']
                }
            }
        });

    } catch (error) {
        const logger = require('../utils/logger');
        logger.error('Get permissions list error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

/**
 * @route   POST /api/role/bulk-assign
 * @desc    Bulk assign roles to multiple users
 * @access  Private - DC only
 */
router.post('/bulk-assign', [
    authMiddleware.verifyToken,
    authMiddleware.authorize('dc'),
    authMiddleware.sensitiveOperationLimit,
    body('assignments')
        .isArray({ min: 1 })
        .withMessage('Assignments must be a non-empty array'),
    body('assignments.*.userId')
        .isMongoId()
        .withMessage('Invalid user ID format'),
    body('assignments.*.newRole')
        .isIn(['student', 'warden', 'dc'])
        .withMessage('Invalid role specified')
], async (req, res) => {
    try {
        const { assignments } = req.body;
        const User = require('../models/User');
        const AccessLog = require('../models/AccessLog');
        const logger = require('../utils/logger');
        const results = [];

        const requestInfo = {
            ip: req.ip || 'unknown',
            userAgent: req.get('User-Agent') || 'unknown'
        };

        // Process each assignment
        for (const assignment of assignments) {
            try {
                const { userId, newRole } = assignment;
                
                // Find user
                const user = await User.findById(userId);
                if (!user || !user.security.isActive) {
                    results.push({
                        userId,
                        success: false,
                        message: 'User not found'
                    });
                    continue;
                }

                // Check if role change is needed
                if (user.role === newRole) {
                    results.push({
                        userId,
                        studentId: user.studentId,
                        success: false,
                        message: 'User already has this role'
                    });
                    continue;
                }

                const oldRole = user.role;

                // Update user role
                user.role = newRole;
                await user.save();

                // Log role change
                await AccessLog.logAccess({
                    userId: req.user.userId,
                    studentId: req.user.studentId,
                    action: 'BULK_ROLE_CHANGE',
                    result: 'SUCCESS',
                    details: {
                        targetUserId: userId,
                        targetStudentId: user.studentId,
                        oldRole,
                        newRole
                    },
                    session: requestInfo
                });

                results.push({
                    userId,
                    studentId: user.studentId,
                    success: true,
                    oldRole,
                    newRole,
                    message: 'Role updated successfully'
                });

                logger.info(`Bulk role change: ${user.studentId} from ${oldRole} to ${newRole}`, {
                    changedBy: req.user.userId,
                    targetUserId: userId
                });

            } catch (error) {
                results.push({
                    userId: assignment.userId,
                    success: false,
                    message: 'Internal error processing assignment'
                });
            }
        }

        const successCount = results.filter(r => r.success).length;
        const failureCount = results.filter(r => !r.success).length;

        logger.info(`Bulk role assignment completed by ${req.user.studentId}`, {
            totalAssignments: assignments.length,
            successCount,
            failureCount,
            executedBy: req.user.userId
        });

        res.json({
            success: true,
            message: `Bulk role assignment completed. ${successCount} successful, ${failureCount} failed.`,
            data: {
                results,
                summary: {
                    total: assignments.length,
                    successful: successCount,
                    failed: failureCount
                }
            }
        });

    } catch (error) {
        const logger = require('../utils/logger');
        logger.error('Bulk role assignment error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

module.exports = router;