import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Users, UserPlus, Shield, Edit, Trash2, Mail, Phone } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { toast } from '@/components/ui/use-toast';

const UserManagement = () => {
  const [users, setUsers] = useState([]);

  const roles = [
    {
      name: 'Administrator',
      description: 'Full system access and user management',
      color: 'bg-red-500'
    },
    { name: 'Security Analyst', description: 'Monitor, investigate, and report on threats', color: 'bg-blue-500' },
    { name: 'Viewer', description: 'Read-only access to dashboards and reports', color: 'bg-green-500' }
  ];

  const handleUserAction = (action, userId) => {
    toast({
      title: "🚧 This feature isn't implemented yet—but don't worry! You can request it in your next prompt! 🚀"
    });
  };

  return (
    <div className="space-y-6">
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        className="flex items-center justify-between"
      >
        <div>
          <h1 className="text-3xl font-bold text-white mb-2">User Management</h1>
          <p className="text-slate-400">Manage users, roles, and permissions</p>
        </div>
        
        <Button onClick={() => handleUserAction('add')} className="bg-blue-600 hover:bg-blue-700">
          <UserPlus className="w-4 h-4 mr-2" />
          Add New User
        </Button>
      </motion.div>

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="grid grid-cols-1 md:grid-cols-3 gap-6"
      >
        {roles.map((role) => (
          <div key={role.name} className="glass-card p-6 rounded-xl">
            <div className="flex items-center justify-between mb-4">
              <div className={`w-12 h-12 ${role.color} rounded-lg flex items-center justify-center`}>
                <Shield className="w-6 h-6 text-white" />
              </div>
              <span className="text-2xl font-bold text-white">
                {users.filter(u => u.role === role.name).length}
              </span>
            </div>
            <h3 className="text-lg font-semibold text-white mb-1">{role.name}</h3>
            <p className="text-sm text-slate-400">{role.description}</p>
          </div>
        ))}
      </motion.div>

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
        className="glass-card p-6 rounded-xl"
      >
        <h2 className="text-xl font-semibold text-white mb-4 flex items-center">
          <Users className="w-5 h-5 mr-2 text-blue-400" />
          All Users ({users.length})
        </h2>
        
        {users.length === 0 ? (
          <div className="text-center py-8 text-slate-400">
            <p>No users found.</p>
            <p className="text-sm">Click "Add New User" to create a user.</p>
          </div>
        ) : (
          <div className="space-y-3">
            {users.map((user, index) => (
              <motion.div
                key={user.id}
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: index * 0.1 }}
                className="flex items-center justify-between p-4 bg-slate-800/50 rounded-lg border border-slate-700/50 hover:border-slate-600/50 transition-all duration-200"
              >
                <div className="flex items-center space-x-4">
                  <div className="w-12 h-12 bg-gradient-to-br from-blue-500 to-purple-600 rounded-full flex items-center justify-center text-white font-bold text-lg">
                    {user.name.split(' ').map(n => n[0]).join('')}
                  </div>
                  <div>
                    <h3 className="font-medium text-white">{user.name}</h3>
                    <div className="flex items-center space-x-2 text-sm text-slate-400">
                      <Mail className="w-3 h-3" />
                      <span>{user.email}</span>
                    </div>
                    <div className="flex items-center space-x-2 text-sm text-slate-400">
                      <Phone className="w-3 h-3" />
                      <span>{user.phone}</span>
                    </div>
                  </div>
                </div>
                
                <div className="flex items-center space-x-6">
                  <div>
                    <div className="text-sm font-medium text-white">{user.role}</div>
                    <div className="text-xs text-slate-400">{user.department}</div>
                  </div>
                  
                  <div>
                    <div className={`px-2 py-1 rounded-full text-xs font-medium ${
                      user.status === 'active' ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'
                    }`}>
                      {user.status.toUpperCase()}
                    </div>
                    <div className="text-xs text-slate-500 mt-1">Last login: {user.lastLogin}</div>
                  </div>
                  
                  <div className="flex space-x-2">
                    <Button variant="outline" size="icon" onClick={() => handleUserAction('edit', user.id)}>
                      <Edit className="w-4 h-4" />
                    </Button>
                    <Button variant="destructive" size="icon" onClick={() => handleUserAction('delete', user.id)}>
                      <Trash2 className="w-4 h-4" />
                    </Button>
                  </div>
                </div>
              </motion.div>
            ))}
          </div>
        )}
      </motion.div>
    </div>
  );
};

export default UserManagement;