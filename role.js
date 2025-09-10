const mongoose = require('mongoose');

const roleSchema = new mongoose.Schema({
    name: {
        type: String,
        required: [true, 'Role name is required'],
        unique: true,
        enum: ['student', 'warden', 'dc'],
        lowercase: true
    },
    displayName: {
        type: String,
        required: [true, 'Display name is required']
    },
    description: {
        type: String,
        required: [true, 'Role description is required']
    },
    permissions: {
        // Dashboard access
        canViewDashboard: {
            type: Boolean,
            default: true
        },
        
        // User management
        canViewUsers: {
            type: Boolean,
            default: false
        },
        canCreateUsers: {
            type: Boolean,
            default: false
        },
        canEditUsers: {
            type: Boolean,
            default: false
        },
        canDeleteUsers: {
            type: Boolean,
            default: false
        },
        
        // Attendance management
        canViewAttendance: {
            type: Boolean,
            default: false
        },
        canMarkAttendance: {
            type: Boolean,
            default: false
        },
        canEditAttendance: {
            type: Boolean,
            default: false
        },
        canGenerateAttendanceReports: {
            type: Boolean,
            default: false
        },
        
        // Room management
        canViewRooms: {
            type: Boolean,
            default: false
        },
        canManageRooms: {
            type: Boolean,
            default: false
        },
        
        // Complaint management
        canViewComplaints: {
            type: Boolean,
            default: false
        },
        canCreateComplaints: {
            type: Boolean,
            default: false
        },
        canResolveComplaints: {
            type: Boolean,
            default: false
        },
        
        // Notice management
        canViewNotices: {
            type: Boolean,
            default: true
        },
        canCreateNotices: {
            type: Boolean,
            default: false
        },
        canEditNotices: {
            type: Boolean,
            default: false
        },
        canDeleteNotices: {
            type: Boolean,
            default: false
        },
        
        // Fee management
        canViewFees: {
            type: Boolean,
            default: false
        },
        canManageFees: {
            type: Boolean,
            default: false
        },
        
        // Reports
        canGenerateReports: {
            type: Boolean,
            default: false
        },
        
        // System administration
        canManageSystem: {
            type: Boolean,
            default: false
        },
        canViewLogs: {
            type: Boolean,
            default: false
        }
    },
    isActive: {
        type: Boolean,
        default: true
    }
}, {
    timestamps: true
});

// Pre-save middleware to set permissions based on role
roleSchema.pre('save', function(next) {
    switch(this.name) {
        case 'student':
            this.permissions = {
                canViewDashboard: true,
                canViewUsers: false,
                canCreateUsers: false,
                canEditUsers: false,
                canDeleteUsers: false,
                canViewAttendance: true,
                canMarkAttendance: false,
                canEditAttendance: false,
                canGenerateAttendanceReports: false,
                canViewRooms: true,
                canManageRooms: false,
                canViewComplaints: true,
                canCreateComplaints: true,
                canResolveComplaints: false,
                canViewNotices: true,
                canCreateNotices: false,
                canEditNotices: false,
                canDeleteNotices: false,
                canViewFees: true,
                canManageFees: false,
                canGenerateReports: false,
                canManageSystem: false,
                canViewLogs: false
            };
            break;
            
        case 'warden':
            this.permissions = {
                canViewDashboard: true,
                canViewUsers: true,
                canCreateUsers: true,
                canEditUsers: true,
                canDeleteUsers: false,
                canViewAttendance: true,
                canMarkAttendance: true,
                canEditAttendance: true,
                canGenerateAttendanceReports: true,
                canViewRooms: true,
                canManageRooms: true,
                canViewComplaints: true,
                canCreateComplaints: false,
                canResolveComplaints: true,
                canViewNotices: true,
                canCreateNotices: true,
                canEditNotices: true,
                canDeleteNotices: true,
                canViewFees: true,
                canManageFees: true,
                canGenerateReports: true,
                canManageSystem: false,
                canViewLogs: true
            };
            break;
            
        case 'dc':
            this.permissions = {
                canViewDashboard: true,
                canViewUsers: true,
                canCreateUsers: true,
                canEditUsers: true,
                canDeleteUsers: true,
                canViewAttendance: true,
                canMarkAttendance: true,
                canEditAttendance: true,
                canGenerateAttendanceReports: true,
                canViewRooms: true,
                canManageRooms: true,
                canViewComplaints: true,
                canCreateComplaints: false,
                canResolveComplaints: true,
                canViewNotices: true,
                canCreateNotices: true,
                canEditNotices: true,
                canDeleteNotices: true,
                canViewFees: true,
                canManageFees: true,
                canGenerateReports: true,
                canManageSystem: true,
                canViewLogs: true
            };
            break;
    }
    next();
});

// Method to check if role has specific permission
roleSchema.methods.hasPermission = function(permission) {
    return this.permissions[permission] === true;
};

// Static method to get role by name
roleSchema.statics.findByName = function(roleName) {
    return this.findOne({ name: roleName.toLowerCase() });
};

module.exports = mongoose.model('Role', roleSchema);