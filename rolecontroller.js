const Role = require('../models/Role');
const User = require('../models/User');
const AccessLog = require('../models/AccessLog');
const logger = require('../utils/logger');

class RoleController {
    // Get all available roles
    async getRoles(req, res) {
        try {
            const roles = await Role.find({ isActive: true })
                .select('name displayName description permissions');

            res.json({
                success: true,
                data: roles
            });

        } catch (error) {
            logger.error('Get roles error:', error);
            res.status(500).json({
                success: false,
                message: 'Internal server error'
            });
        }
    }

    // Get specific role details
    async getRole(req, res) {
        try {
            const { roleName } = req.params;
            
            const role = await Role.findByName(roleName);
            if (!role || !role.isActive) {
                return res.status(404).json({
                    success: false,
                    message: 'Role not found'
                });
            }

            res.json({
                success: true,
                data: role
            });

        } catch (error) {
            logger.error('Get role error:', error);
            res.status(500).json({
                success: false,
                message: 'Internal server error'
            });
        }
    }

    // Check user permissions
    async checkPermission(req, res) {
        try {
            const { permission } = req.params;
            const userRole = req.user.role;

            const role = await Role.findByName(userRole);
            if (!role || !role.isActive) {
                return res.status(404).json({
                    success: false,
                    message: 'Role not found'
                });
            }

            const hasPermission = role.hasPermission(permission);

            res.json({
                success: true,
                data: {
                    permission,
                    hasPermission,
                    role: userRole
                }
            });

        } catch (error) {
            logger.error('Check permission error:', error);
            res.status(500).json({
                success: false,
                message: 'Internal server error'
            });
        }
    }

    // Assign role to user (DC only)
    async assignRole(req, res) {
        try {
            // Only DC can assign roles
            if (req.user.role !== 'dc') {
                return res.status(403).json({
                    success: false,
                    message: 'Only DC can assign roles'
                });
            }

            const { userId, newRole } = req.body;
            const requestInfo = {
                ip: req.ip || req.connection.remoteAddress || 'unknown',
                userAgent: req.get('User-Agent') || 'unknown'
            };

            // Validate new role
            if (!['student', 'warden', 'dc'].includes(newRole)) {
                return res.status(400).json({
                    success: false,
                    message: 'Invalid role specified'
                });
            }

            // Find user
            const user = await User.findById(userId);
            if (!user || !user.security.isActive) {
                return res.status(404).json({
                    success: false,
                    message: 'User not found'
                });
            }

            // Check if role change is needed
            if (user.role === newRole) {
                return res.status(400).json({
                    success: false,
                    message: 'User already has this role'
                });
            }

            const oldRole = user.role;

            // Update user role
            user.role = newRole;
            await user.save();

            // Log role change
            await AccessLog.logAccess({
                userId: req.user.userId,
                studentId: req.user.studentId,
                action: 'ROLE_CHANGE',
                result: 'SUCCESS',
                details: {
                    targetUserId: userId,
                    targetStudentId: user.studentId,
                    oldRole,
                    newRole
                },
                session: requestInfo
            });

            logger.info(`Role changed: ${user.studentId} from ${oldRole} to ${newRole} by ${req.user.studentId}`, {
                changedBy: req.user.userId,
                targetUserId: userId
            });

            res.json({
                success: true,
                message: 'Role assigned successfully',
                data: {
                    userId: user._id,
                    studentId: user.studentId,
                    oldRole,
                    newRole
                }
            });

        } catch (error) {
            logger.error('Assign role error:', error);
            res.status(500).json({
                success: false,
                message: 'Internal server error'
            });
        }
    }

    // Get role statistics (DC only)
    async getRoleStats(req, res) {
        try {
            if (req.user.role !== 'dc') {
                return res.status(403).json({
                    success: false,
                    message: 'Insufficient permissions'
                });
            }

            const stats = await User.aggregate([
                {
                    $match: { 'security.isActive': true }
                },
                {
                    $group: {
                        _id: '$role',
                        count: { $sum: 1 },
                        lastLogin: { $max: '$security.lastLogin' }
                    }
                },
                {
                    $lookup: {
                        from: 'roles',
                        localField: '_id',
                        foreignField: 'name',
                        as: 'roleDetails'
                    }
                },
                {
                    $project: {
                        role: '$_id',
                        count: 1,
                        lastLogin: 1,
                        displayName: { $arrayElemAt: ['$roleDetails.displayName', 0] },
                        description: { $arrayElemAt: ['$roleDetails.description', 0] }
                    }
                }
            ]);

            // Get recent role changes
            const recentRoleChanges = await AccessLog.find({
                action: 'ROLE_CHANGE',
                result: 'SUCCESS'
            })
            .sort({ timestamp: -1 })
            .limit(10)
            .populate('userId', 'studentId profile.firstName profile.lastName');

            res.json({
                success: true,
                data: {
                    roleDistribution: stats,
                    recentRoleChanges,
                    totalUsers: stats.reduce((sum, role) => sum + role.count, 0),
                    lastUpdated: new Date()
                }
            });

        } catch (error) {
            logger.error('Get role stats error:', error);
            res.status(500).json({
                success: false,
                message: 'Internal server error'
            });
        }
    }

    // Initialize default roles (run once during setup)
    async initializeRoles(req, res) {
        try {
            // Only DC can initialize roles
            if (req.user && req.user.role !== 'dc') {
                return res.status(403).json({
                    success: false,
                    message: 'Only DC can initialize roles'
                });
            }

            const defaultRoles = [
                {
                    name: 'student',
                    displayName: 'Student',
                    description: 'Hostel student with basic access to view information and submit complaints'
                },
                {
                    name: 'warden',
                    displayName: 'Warden',
                    description: 'Hostel warden with administrative privileges for managing students and hostel operations'
                },
                {
                    name: 'dc',
                    displayName: 'Deputy Chief',
                    description: 'System administrator with full access to all features and user management'
                }
            ];

            const createdRoles = [];
            
            for (const roleData of defaultRoles) {
                const existingRole = await Role.findOne({ name: roleData.name });
                
                if (!existingRole) {
                    const role = new Role(roleData);
                    await role.save();
                    createdRoles.push(role);
                    logger.info(`Role created: ${role.name}`);
                } else {
                    logger.info(`Role already exists: ${roleData.name}`);
                }
            }

            res.json({
                success: true,
                message: 'Roles initialized successfully',
                data: {
                    created: createdRoles.length,
                    roles: createdRoles
                }
            });

        } catch (error) {
            logger.error('Initialize roles error:', error);
            res.status(500).json({
                success: false,
                message: 'Internal server error'
            });
        }
    }

    // Get users by role
    async getUsersByRole(req, res) {
        try {
            // Check permissions
            if (!['warden', 'dc'].includes(req.user.role)) {
                return res.status(403).json({
                    success: false,
                    message: 'Insufficient permissions'
                });
            }

            const { roleName } = req.params;
            const page = parseInt(req.query.page) || 1;
            const limit = parseInt(req.query.limit) || 10;

            // Validate role name
            if (!['student', 'warden', 'dc'].includes(roleName)) {
                return res.status(400).json({
                    success: false,
                    message: 'Invalid role name'
                });
            }

            // Get users with specified role
            const users = await User.find({
                role: roleName,
                'security.isActive': true
            })
            .select('-password -security.passwordResetToken')
            .sort({ createdAt: -1 })
            .limit(limit * 1)
            .skip((page - 1) * limit);

            const total = await User.countDocuments({
                role: roleName,
                'security.isActive': true
            });

            res.json({
                success: true,
                data: {
                    users,
                    role: roleName,
                    pagination: {
                        page,
                        limit,
                        total,
                        pages: Math.ceil(total / limit)
                    }
                }
            });

        } catch (error) {
            logger.error('Get users by role error:', error);
            res.status(500).json({
                success: false,
                message: 'Internal server error'
            });
        }
    }

    // Get permission matrix (DC only)
    async getPermissionMatrix(req, res) {
        try {
            if (req.user.role !== 'dc') {
                return res.status(403).json({
                    success: false,
                    message: 'Only DC can view permission matrix'
                });
            }

            const roles = await Role.find({ isActive: true })
                .select('name displayName permissions');

            // Create permission matrix
            const allPermissions = new Set();
            roles.forEach(role => {
                Object.keys(role.permissions).forEach(permission => {
                    allPermissions.add(permission);
                });
            });

            const permissionMatrix = Array.from(allPermissions).map(permission => {
                const rolePermissions = {};
                roles.forEach(role => {
                    rolePermissions[role.name] = role.permissions[permission] || false;
                });

                return {
                    permission,
                    roles: rolePermissions
                };
            });

            res.json({
                success: true,
                data: {
                    roles: roles.map(role => ({
                        name: role.name,
                        displayName: role.displayName
                    })),
                    permissions: permissionMatrix
                }
            });

        } catch (error) {
            logger.error('Get permission matrix error:', error);
            res.status(500).json({
                success: false,
                message: 'Internal server error'
            });
        }
    }

    // Update role permissions (DC only)
    async updateRolePermissions(req, res) {
        try {
            if (req.user.role !== 'dc') {
                return res.status(403).json({
                    success: false,
                    message: 'Only DC can update role permissions'
                });
            }

            const { roleName } = req.params;
            const { permissions } = req.body;
            const requestInfo = {
                ip: req.ip || req.connection.remoteAddress || 'unknown',
                userAgent: req.get('User-Agent') || 'unknown'
            };

            // Find role
            const role = await Role.findByName(roleName);
            if (!role || !role.isActive) {
                return res.status(404).json({
                    success: false,
                    message: 'Role not found'
                });
            }

            // Store old permissions for logging
            const oldPermissions = { ...role.permissions };

            // Update permissions
            Object.keys(permissions).forEach(permission => {
                if (role.permissions.hasOwnProperty(permission)) {
                    role.permissions[permission] = Boolean(permissions[permission]);
                }
            });

            await role.save();

            // Log permission update
            await AccessLog.logAccess({
                userId: req.user.userId,
                studentId: req.user.studentId,
                action: 'ROLE_PERMISSIONS_UPDATED',
                result: 'SUCCESS',
                details: {
                    roleName,
                    oldPermissions,
                    newPermissions: role.permissions
                },
                session: requestInfo
            });

            logger.info(`Role permissions updated: ${roleName} by ${req.user.studentId}`, {
                updatedBy: req.user.userId,
                roleName
            });

            res.json({
                success: true,
                message: 'Role permissions updated successfully',
                data: {
                    roleName: role.name,
                    displayName: role.displayName,
                    permissions: role.permissions
                }
            });

        } catch (error) {
            logger.error('Update role permissions error:', error);
            res.status(500).json({
                success: false,
                message: 'Internal server error'
            });
        }
    }
}

module.exports = new RoleController();