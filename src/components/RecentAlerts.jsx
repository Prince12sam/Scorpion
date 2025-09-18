import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { AlertTriangle, Shield, Eye, Clock, ChevronRight, X, Info, CheckSquare } from 'lucide-react';
import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";

const RecentAlerts = () => {
  const [alerts, setAlerts] = useState([]);
  const [selectedAlert, setSelectedAlert] = useState(null);

  const getSeverityIcon = (severity) => {
    switch (severity) {
      case 'critical': return AlertTriangle;
      case 'high': return AlertTriangle;
      case 'medium': return Eye;
      case 'low': return Shield;
      default: return Shield;
    }
  };

  const getSeverityClass = (severity) => {
    switch (severity) {
      case 'critical': return 'threat-critical';
      case 'high': return 'threat-high';
      case 'medium': return 'threat-medium';
      case 'low': return 'threat-low';
      default: return 'threat-info';
    }
  };

  return (
    <>
      <div className="glass-card p-6 rounded-xl">
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-xl font-semibold text-white flex items-center">
            <AlertTriangle className="w-5 h-5 mr-2 text-red-400" />
            Live Security Alerts
          </h2>
          <Button variant="outline" size="sm" className="text-slate-400 border-slate-600 hover:border-slate-500">
            View All
          </Button>
        </div>

        <div className="space-y-3 max-h-96 overflow-y-auto">
          <AnimatePresence>
            {alerts.length === 0 ? (
              <div className="text-center py-12 text-slate-400">
                <p>Awaiting live alerts...</p>
                <p className="text-sm">The system is actively monitoring for threats.</p>
              </div>
            ) : (
              alerts.map((alert, index) => {
                const Icon = getSeverityIcon(alert.severity);
                return (
                  <motion.div
                    key={alert.id}
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: 20 }}
                    transition={{ duration: 0.5, delay: index * 0.05 }}
                    className="flex items-center space-x-4 p-4 bg-slate-800/50 rounded-lg border border-slate-700/50 hover:border-slate-600/50 transition-all duration-200 cursor-pointer group"
                    onClick={() => setSelectedAlert(alert)}
                  >
                    <div className={`w-8 h-8 rounded-full flex items-center justify-center ${getSeverityClass(alert.severity)}`}>
                      <Icon className="w-4 h-4" />
                    </div>
                    
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center space-x-2 mb-1">
                        <span className={`text-xs font-medium px-2 py-1 rounded-full ${getSeverityClass(alert.severity)}`}>
                          {alert.type}
                        </span>
                        <div className="flex items-center space-x-1 text-xs text-slate-400">
                          <Clock className="w-3 h-3" />
                          <span>{alert.time}</span>
                        </div>
                      </div>
                      <p className="text-sm text-slate-300 truncate group-hover:text-white transition-colors">
                        {alert.message}
                      </p>
                    </div>
                    
                    <ChevronRight className="w-4 h-4 text-slate-400 group-hover:text-white transition-colors" />
                  </motion.div>
                );
              })
            )}
          </AnimatePresence>
        </div>

        <div className="mt-4 pt-4 border-t border-slate-700">
          <div className="grid grid-cols-4 gap-4 text-center">
            <div>
              <div className="text-lg font-bold text-red-400">
                {alerts.filter(a => a.severity === 'critical').length}
              </div>
              <div className="text-xs text-slate-400">Critical</div>
            </div>
            <div>
              <div className="text-lg font-bold text-orange-400">
                {alerts.filter(a => a.severity === 'high').length}
              </div>
              <div className="text-xs text-slate-400">High</div>
            </div>
            <div>
              <div className="text-lg font-bold text-yellow-400">
                {alerts.filter(a => a.severity === 'medium').length}
              </div>
              <div className="text-xs text-slate-400">Medium</div>
            </div>
            <div>
              <div className="text-lg font-bold text-blue-400">
                {alerts.filter(a => a.severity === 'low').length}
              </div>
              <div className="text-xs text-slate-400">Low</div>
            </div>
          </div>
        </div>
      </div>

      <Dialog open={!!selectedAlert} onOpenChange={() => setSelectedAlert(null)}>
        <DialogContent className="sm:max-w-[625px] bg-slate-900 border-slate-700 text-white">
          {selectedAlert && (
            <>
              <DialogHeader>
                <DialogTitle className={`flex items-center text-2xl ${getSeverityClass(selectedAlert.severity)}`}>
                  <div className={`mr-3 p-2 rounded-full ${getSeverityClass(selectedAlert.severity)}`}>
                    {React.createElement(getSeverityIcon(selectedAlert.severity), { className: "w-6 h-6" })}
                  </div>
                  {selectedAlert.type} Alert
                </DialogTitle>
                <DialogDescription className="text-slate-400 pt-2">
                  {selectedAlert.message}
                </DialogDescription>
              </DialogHeader>
              <div className="grid gap-6 py-4">
                <div className="space-y-4">
                  <div>
                    <h4 className="font-semibold text-lg mb-2 flex items-center text-blue-400"><Info className="w-5 h-5 mr-2"/>Vulnerability Details</h4>
                    <p className="text-slate-300 bg-slate-800/50 p-3 rounded-md border border-slate-700">{selectedAlert.details}</p>
                  </div>
                  <div>
                    <h4 className="font-semibold text-lg mb-2 flex items-center text-green-400"><CheckSquare className="w-5 h-5 mr-2"/>Recommended Solution</h4>
                    <p className="text-slate-300 bg-slate-800/50 p-3 rounded-md border border-slate-700">{selectedAlert.recommendation}</p>
                  </div>
                </div>
              </div>
            </>
          )}
        </DialogContent>
      </Dialog>
    </>
  );
};

export default RecentAlerts;