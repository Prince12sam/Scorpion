import React, { useState, useEffect } from 'react';import React, { useState, useEffect } from 'react';import React, { useState, useEffect } from 'react';import React, { useState, useEffect } from 'react';

import { motion } from 'framer-motion';

import { FileCheck2, AlertTriangle, RefreshCw, FolderPlus } from 'lucide-react';import { motion } from 'framer-motion';

import { Button } from '@/components/ui/button';

import { toast } from '@/components/ui/use-toast';import { FileCheck2, AlertTriangle, CheckCircle, Clock, Filter, RefreshCw, Eye, FolderPlus } from 'lucide-react';import { motion } from 'framer-motion';import { motion } from 'framer-motion';

import apiClient from '@/lib/api-client';

import { Button } from '@/components/ui/button';

const FileIntegrityMonitor = () => {

  const [fimAlerts, setFimAlerts] = useState([]);import { toast } from '@/components/ui/use-toast';import { FileCheck2, AlertTriangle, CheckCircle, Clock, Filter, RefreshCw, Eye, FolderPlus } from 'lucide-react';import { FileCheck2, AlertTriangle, CheckCircle, Clock, Filter, RefreshCw, Eye, FolderPlus } from 'lucide-react';

  const [watchedPaths, setWatchedPaths] = useState([]);

  const [newPath, setNewPath] = useState('');import apiClient from '@/lib/api-client';

  const [autoRefresh, setAutoRefresh] = useState(true);

import { Button } from '@/components/ui/button';import { Button } from '@/components/ui/button';

  useEffect(() => {

    fetchFIMAlerts();const FileIntegrityMonitor = () => {

    fetchWatchedPaths();

      const [fimAlerts, setFimAlerts] = useState([]);import { toast } from '@/components/ui/use-toast';import { toast } from '@/components/ui/use-toast';

    let interval;

    if (autoRefresh) {  const [filterType, setFilterType] = useState('all');

      interval = setInterval(fetchFIMAlerts, 5000);

    }  const [autoRefresh, setAutoRefresh] = useState(true);import apiClient from '@/lib/api-client';import apiClient from '@/lib/api-client';

    

    return () => {  const [watchedPaths, setWatchedPaths] = useState([]);

      if (interval) clearInterval(interval);

    };  const [newPath, setNewPath] = useState('');

  }, [autoRefresh]);

  const [monitoring, setMonitoring] = useState(false);

  const fetchFIMAlerts = async () => {

    try {const FileIntegrityMonitor = () => {const FileIntegrityMonitor = () => {

      const data = await apiClient.get('/fim/alerts');

      setFimAlerts(data.alerts || []);  useEffect(() => {

    } catch (error) {

      console.error('Error fetching FIM alerts:', error);    fetchFIMAlerts();  const [fimAlerts, setFimAlerts] = useState([]);  const [fimAlerts, setFimAlerts] = useState([]);

    }

  };    fetchWatchedPaths();



  const fetchWatchedPaths = async () => {      const [filterType, setFilterType] = useState('all');  const [filterType, setFilterType] = useState('all');

    try {

      const data = await apiClient.get('/fim/watched');    let interval;

      setWatchedPaths(data.paths || []);

    } catch (error) {    if (autoRefresh) {  const [autoRefresh, setAutoRefresh] = useState(true);  const [autoRefresh, setAutoRefresh] = useState(true);

      console.error('Error fetching watched paths:', error);

    }      interval = setInterval(fetchFIMAlerts, 5000);

  };

    }  const [watchedPaths, setWatchedPaths] = useState([]);  const [watchedPaths, setWatchedPaths] = useState([]);

  const addWatchPath = async () => {

    if (!newPath.trim()) {    

      toast({

        title: "Invalid Path",    return () => {  const [newPath, setNewPath] = useState('');  const [newPath, setNewPath] = useState('');

        description: "Please enter a valid path to monitor",

        variant: "destructive"      if (interval) clearInterval(interval);

      });

      return;      apiClient.cancelRequest('/fim/alerts');  const [monitoring, setMonitoring] = useState(false);  const [monitoring, setMonitoring] = useState(false);

    }

      apiClient.cancelRequest('/fim/watched');

    try {

      await apiClient.post('/fim/watch', { path: newPath.trim() });    };

      

      toast({  }, [autoRefresh]);

        title: "Path Added",

        description: `Now monitoring: ${newPath}`,  useEffect(() => {  useEffect(() => {

      });

      setNewPath('');  const fetchFIMAlerts = async () => {

      fetchWatchedPaths();

    } catch (error) {    try {    fetchFIMAlerts();    fetchFIMAlerts();

      toast({

        title: "Failed to Add Path",      const data = await apiClient.get('/fim/alerts');

        description: error.message,

        variant: "destructive"      setFimAlerts(data.alerts || []);    fetchWatchedPaths();    fetchWatchedPaths();

      });

    }    } catch (error) {

  };

      if (error.name !== 'AbortError') {        

  const startMonitoring = async () => {

    try {        console.error('Error fetching FIM alerts:', error);

      await apiClient.post('/fim/start');

      toast({      }    let interval;    let interval;

        title: "Monitoring Started",

        description: "File integrity monitoring is now active",    }

      });

    } catch (error) {  };    if (autoRefresh) {    if (autoRefresh) {

      toast({

        title: "Failed to Start Monitoring",

        description: "Could not start file integrity monitoring",

        variant: "destructive"  const fetchWatchedPaths = async () => {      interval = setInterval(fetchFIMAlerts, 5000);      interval = setInterval(fetchFIMAlerts, 5000);

      });

    }    try {

  };

      const data = await apiClient.get('/fim/watched');    }    }

  return (

    <div className="space-y-6">      setWatchedPaths(data.paths || []);

      <motion.div 

        initial={{ opacity: 0, y: -20 }}     } catch (error) {        

        animate={{ opacity: 1, y: 0 }} 

        className="flex items-center justify-between"      if (error.name !== 'AbortError') {

      >

        <div>        console.error('Error fetching watched paths:', error);    return () => {    return () => {

          <h1 className="text-3xl font-bold text-white mb-2">File Integrity Monitoring</h1>

          <p className="text-slate-400">Detect changes to critical system and application files.</p>      }

        </div>

        <Button     }      if (interval) clearInterval(interval);      if (interval) clearInterval(interval);

          variant="outline" 

          size="sm"   };

          onClick={() => setAutoRefresh(!autoRefresh)} 

          className={autoRefresh ? 'border-green-500 text-green-400' : 'border-slate-600 text-slate-400'}      apiClient.cancelRequest('/fim/alerts');      apiClient.cancelRequest('/fim/alerts');

        >

          <RefreshCw className={`w-4 h-4 mr-2 ${autoRefresh ? 'animate-spin' : ''}`} />  const getSeverityColor = (severity) => {

          Auto Refresh

        </Button>    switch (severity) {      apiClient.cancelRequest('/fim/watched');      apiClient.cancelRequest('/fim/watched');

      </motion.div>

      case 'critical': return 'text-red-400 bg-red-500/20 border-red-500/30';

      <motion.div 

        initial={{ opacity: 0, y: 20 }}       case 'high': return 'text-orange-400 bg-orange-500/20 border-orange-500/30';    };    };

        animate={{ opacity: 1, y: 0 }} 

        transition={{ delay: 0.1 }}       case 'medium': return 'text-yellow-400 bg-yellow-500/20 border-yellow-500/30';

        className="glass-card p-6 rounded-xl"

      >      case 'low': return 'text-blue-400 bg-blue-500/20 border-blue-500/30';  }, [autoRefresh]);  }, [autoRefresh]);

        <h2 className="text-xl font-semibold text-white mb-6 flex items-center">

          <FileCheck2 className="w-5 h-5 mr-2 text-red-400" />      default: return 'text-slate-400 bg-slate-500/20 border-slate-500/30';

          FIM Alerts ({fimAlerts.length})

        </h2>    }

        {fimAlerts.length === 0 ? (

          <div className="text-center py-8 text-slate-400">  };

            <p>No file integrity alerts.</p>

            <p className="text-sm">The system is monitoring for file changes.</p>  const fetchFIMAlerts = async () => {  const fetchFIMAlerts = async () => {

          </div>

        ) : (  const getChangeTypeColor = (change) => {

          <div className="space-y-4">

            {fimAlerts.map((alert, index) => (    switch (change) {    try {    try {

              <div key={alert.id} className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50">

                <div className="flex items-start justify-between">      case 'Added': return 'bg-green-500/20 text-green-400';

                  <div className="flex-1">

                    <h3 className="text-lg font-semibold text-white font-mono">{alert.file}</h3>      case 'Modified': return 'bg-yellow-500/20 text-yellow-400';      const data = await apiClient.get('/fim/alerts');      const data = await apiClient.get('/fim/alerts');

                    <p className="text-slate-400 mb-2">{alert.details}</p>

                    <div className="text-sm text-slate-500">      case 'Deleted': return 'bg-red-500/20 text-red-400';

                      <span>Change: {alert.change}</span> | 

                      <span> Severity: {alert.severity}</span> |       default: return 'bg-slate-500/20 text-slate-400';      setFimAlerts(data.alerts || []);      setFimAlerts(data.alerts || []);

                      <span> Status: {alert.status}</span>

                    </div>    }

                  </div>

                </div>  };    } catch (error) {    } catch (error) {

              </div>

            ))}

          </div>

        )}  const filteredAlerts = filterType === 'all'      if (error.name !== 'AbortError') {      if (error.name !== 'AbortError') {

      </motion.div>

    ? fimAlerts

      <motion.div 

        initial={{ opacity: 0, y: 20 }}     : fimAlerts.filter(alert => alert.change.toLowerCase() === filterType);        console.error('Error fetching FIM alerts:', error);        console.error('Error fetching FIM alerts:', error);

        animate={{ opacity: 1, y: 0 }} 

        transition={{ delay: 0.2 }} 

        className="glass-card p-6 rounded-xl"

      >  const handleAlertAction = async (alertId, action) => {      }      }

        <h2 className="text-xl font-semibold text-white mb-6 flex items-center">

          <FolderPlus className="w-5 h-5 mr-2 text-green-400" />    try {

          Watched Paths ({watchedPaths.length})

        </h2>      await apiClient.put(`/fim/alert/${alertId}`, { status: action });    }    }

        

        <div className="space-y-4">      

          <div className="flex items-center space-x-4">

            <input      toast({  };  };

              type="text"

              value={newPath}        title: "Action Complete",

              onChange={(e) => setNewPath(e.target.value)}

              placeholder="Enter path to monitor (e.g., C:\\Windows\\System32)"        description: `Alert ${action} successfully`,

              className="flex-1 px-4 py-2 bg-slate-800/50 border border-slate-700 rounded-lg text-white placeholder:text-slate-400 focus:border-blue-500 focus:outline-none"

            />      });

            <Button onClick={addWatchPath} className="bg-green-600 hover:bg-green-700">

              <FolderPlus className="w-4 h-4 mr-2" />      fetchFIMAlerts();  const fetchWatchedPaths = async () => {  const fetchWatchedPaths = async () => {

              Add Path

            </Button>    } catch (error) {

          </div>

      toast({    try {    try {

          {watchedPaths.length === 0 ? (

            <div className="text-center py-8 text-slate-400">        title: "Action Failed",

              <p>No paths are currently being monitored.</p>

              <p className="text-sm">Add paths above to start monitoring file integrity.</p>        description: "Failed to perform action on alert",      const data = await apiClient.get('/fim/watched');      const data = await apiClient.get('/fim/watched');

            </div>

          ) : (        variant: "destructive"

            <div className="space-y-2">

              {watchedPaths.map((path, index) => (      });      setWatchedPaths(data.paths || []);      setWatchedPaths(data.paths || []);

                <div

                  key={path.id || index}    }

                  className="p-3 bg-slate-800/50 rounded-lg border border-slate-700/50"

                >  };    } catch (error) {    } catch (error) {

                  <div className="flex items-center justify-between">

                    <div className="flex-1">

                      <span className="text-white font-mono text-sm">{path.path || path}</span>

                      <div className="text-xs text-slate-400 mt-1">  const addWatchPath = async () => {      if (error.name !== 'AbortError') {      if (error.name !== 'AbortError') {

                        Added: {path.added ? new Date(path.added).toLocaleString() : 'Unknown'}

                      </div>    if (!newPath.trim()) {

                    </div>

                    <div className="flex items-center space-x-2">      toast({        console.error('Error fetching watched paths:', error);        console.error('Error fetching watched paths:', error);

                      <span className={`px-2 py-1 rounded-full text-xs font-medium ${

                        path.active ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'        title: "Invalid Path",

                      }`}>

                        {path.active ? 'Active' : 'Inactive'}        description: "Please enter a valid path to monitor",      }      }

                      </span>

                    </div>        variant: "destructive"

                  </div>

                </div>      });    }    }

              ))}

            </div>      return;

          )}

    }  };  };

          <div className="flex items-center justify-between pt-4 border-t border-slate-700">

            <div className="text-sm text-slate-400">

              File Integrity Monitoring System

            </div>    try {

            <Button 

              onClick={startMonitoring}      await apiClient.post('/fim/watch', { path: newPath.trim() });

              className="bg-blue-600 hover:bg-blue-700"

            >        const getSeverityColor = (severity) => {  const getSeverityColor = (severity) => {

              Start Monitoring

            </Button>      toast({

          </div>

        </div>        title: "Path Added",    switch (severity) {    switch (severity) {

      </motion.div>

    </div>        description: `Now monitoring: ${newPath}`,

  );

};      });      case 'critical': return 'text-red-400 bg-red-500/20 border-red-500/30';      case 'critical': return 'text-red-400 bg-red-500/20 border-red-500/30';



export default FileIntegrityMonitor;      setNewPath('');

      fetchWatchedPaths();      case 'high': return 'text-orange-400 bg-orange-500/20 border-orange-500/30';      case 'high': return 'text-orange-400 bg-orange-500/20 border-orange-500/30';

    } catch (error) {

      toast({      case 'medium': return 'text-yellow-400 bg-yellow-500/20 border-yellow-500/30';      case 'medium': return 'text-yellow-400 bg-yellow-500/20 border-yellow-500/30';

        title: "Failed to Add Path",

        description: error.message,      case 'low': return 'text-blue-400 bg-blue-500/20 border-blue-500/30';      case 'low': return 'text-blue-400 bg-blue-500/20 border-blue-500/30';

        variant: "destructive"

      });      default: return 'text-slate-400 bg-slate-500/20 border-slate-500/30';      default: return 'text-slate-400 bg-slate-500/20 border-slate-500/30';

    }

  };    }    }



  const startMonitoring = async () => {  };  };

    try {

      await apiClient.post('/fim/start');

      setMonitoring(true);

      toast({  const getChangeTypeColor = (change) => {  const getChangeTypeColor = (change) => {

        title: "Monitoring Started",

        description: "File integrity monitoring is now active",    switch (change) {    switch (change) {

      });

    } catch (error) {      case 'Added': return 'bg-green-500/20 text-green-400';      case 'Added': return 'bg-green-500/20 text-green-400';

      toast({

        title: "Failed to Start Monitoring",      case 'Modified': return 'bg-yellow-500/20 text-yellow-400';      case 'Modified': return 'bg-yellow-500/20 text-yellow-400';

        description: "Could not start file integrity monitoring",

        variant: "destructive"      case 'Deleted': return 'bg-red-500/20 text-red-400';      case 'Deleted': return 'bg-red-500/20 text-red-400';

      });

    }      default: return 'bg-slate-500/20 text-slate-400';      default: return 'bg-slate-500/20 text-slate-400';

  };

    }    }

  return (

    <div className="space-y-6">  };  };

      <motion.div initial={{ opacity: 0, y: -20 }} animate={{ opacity: 1, y: 0 }} className="flex items-center justify-between">

        <div>

          <h1 className="text-3xl font-bold text-white mb-2">File Integrity Monitoring</h1>

          <p className="text-slate-400">Detect changes to critical system and application files.</p>  const filteredAlerts = filterType === 'all'  const filteredAlerts = filterType === 'all'

        </div>

        <Button variant="outline" size="sm" onClick={() => setAutoRefresh(!autoRefresh)} className={autoRefresh ? 'border-green-500 text-green-400' : 'border-slate-600 text-slate-400'}>    ? fimAlerts    ? fimAlerts

          <RefreshCw className={`w-4 h-4 mr-2 ${autoRefresh ? 'animate-spin' : ''}`} />

          Auto Refresh    : fimAlerts.filter(alert => alert.change.toLowerCase() === filterType);    : fimAlerts.filter(alert => alert.change.toLowerCase() === filterType);

        </Button>

      </motion.div>



      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }} className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">  const handleAlertAction = async (alertId, action) => {  const handleAlertAction = async (alertId, action) => {

        <div className="glass-card p-6 rounded-xl">

          <div className="flex items-center justify-between mb-2">    try {    try {

            <div className="w-12 h-12 bg-gradient-to-br from-red-500 to-red-600 rounded-lg flex items-center justify-center">

              <AlertTriangle className="w-6 h-6 text-white" />      await apiClient.put(`/fim/alert/${alertId}`, { status: action });      await apiClient.put(`/fim/alert/${alertId}`, { status: action });

            </div>

            <span className="text-2xl font-bold text-white">{fimAlerts.filter(a => a.severity === 'critical').length}</span>            

          </div>

          <h3 className="text-sm text-slate-400">Critical Alerts</h3>      // Update local state      // Update local state

        </div>

        <div className="glass-card p-6 rounded-xl">      toast({      toast({

          <div className="flex items-center justify-between mb-2">

            <div className="w-12 h-12 bg-gradient-to-br from-yellow-500 to-yellow-600 rounded-lg flex items-center justify-center">        title: "Action Complete",        title: "Action Complete",

              <FileCheck2 className="w-6 h-6 text-white" />

            </div>        description: `Alert ${action} successfully`,        description: `Alert ${action} successfully`,

            <span className="text-2xl font-bold text-white">{fimAlerts.filter(a => a.change === 'Modified').length}</span>

          </div>      });      });

          <h3 className="text-sm text-slate-400">Files Modified</h3>

        </div>      fetchFIMAlerts();      fetchFIMAlerts();

        <div className="glass-card p-6 rounded-xl">

          <div className="flex items-center justify-between mb-2">    } catch (error) {    } catch (error) {

            <div className="w-12 h-12 bg-gradient-to-br from-green-500 to-green-600 rounded-lg flex items-center justify-center">

              <FileCheck2 className="w-6 h-6 text-white" />      toast({      toast({

            </div>

            <span className="text-2xl font-bold text-white">{fimAlerts.filter(a => a.change === 'Added').length}</span>        title: "Action Failed",        title: "Action Failed",

          </div>

          <h3 className="text-sm text-slate-400">Files Added</h3>        description: "Failed to perform action on alert",        description: "Failed to perform action on alert",

        </div>

        <div className="glass-card p-6 rounded-xl">        variant: "destructive"        variant: "destructive"

          <div className="flex items-center justify-between mb-2">

            <div className="w-12 h-12 bg-gradient-to-br from-blue-500 to-blue-600 rounded-lg flex items-center justify-center">      });      });

              <CheckCircle className="w-6 h-6 text-white" />

            </div>    }    }

            <span className="text-2xl font-bold text-white">{fimAlerts.filter(a => a.status === 'resolved').length}</span>

          </div>  };  };

          <h3 className="text-sm text-slate-400">Alerts Resolved</h3>

        </div>

      </motion.div>

  const addWatchPath = async () => {  const addWatchPath = async () => {

      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }} className="glass-card p-6 rounded-xl">

        <div className="flex items-center justify-between mb-4">    if (!newPath.trim()) {    if (!newPath.trim()) {

          <h2 className="text-xl font-semibold text-white flex items-center">

            <Filter className="w-5 h-5 mr-2 text-blue-400" />      toast({      toast({

            Alert Filters

          </h2>        title: "Invalid Path",        title: "Invalid Path",

        </div>

        <div className="flex items-center space-x-4">        description: "Please enter a valid path to monitor",        description: "Please enter a valid path to monitor",

          <span className="text-sm text-slate-400">Filter by change type:</span>

          {['all', 'added', 'modified', 'deleted'].map((type) => (        variant: "destructive"        variant: "destructive"

            <Button key={type} variant={filterType === type ? 'default' : 'outline'} size="sm" onClick={() => setFilterType(type)} className={filterType === type ? 'bg-blue-600' : 'border-slate-600 text-slate-400'}>

              {type.charAt(0).toUpperCase() + type.slice(1)}      });      });

            </Button>

          ))}      return;      return;

        </div>

      </motion.div>    }    }



      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }} className="glass-card p-6 rounded-xl">

        <h2 className="text-xl font-semibold text-white mb-6 flex items-center">

          <FileCheck2 className="w-5 h-5 mr-2 text-red-400" />    try {    try {

          FIM Alerts ({filteredAlerts.length})

        </h2>      await apiClient.post('/fim/watch', { path: newPath.trim() });      await apiClient.post('/fim/watch', { path: newPath.trim() });

        {filteredAlerts.length === 0 ? (

          <div className="text-center py-8 text-slate-400">            

            <p>No file integrity alerts.</p>

            <p className="text-sm">The system is monitoring for file changes.</p>      toast({      toast({

          </div>

        ) : (        title: "Path Added",        title: "Path Added",

          <div className="space-y-4">

            {filteredAlerts.map((alert, index) => (        description: `Now monitoring: ${newPath}`,        description: `Now monitoring: ${newPath}`,

              <motion.div key={alert.id} initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: index * 0.1 }} className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50 hover:border-slate-600/50 transition-all duration-200">

                <div className="flex items-start justify-between">      });      });

                  <div className="flex-1">

                    <div className="flex items-center space-x-3 mb-2">      setNewPath('');      setNewPath('');

                      <h3 className="text-lg font-semibold text-white font-mono truncate">{alert.file}</h3>

                      <span className={`px-2 py-1 rounded-full text-xs font-medium border ${getSeverityColor(alert.severity)}`}>      fetchWatchedPaths();      fetchWatchedPaths();

                        {alert.severity.toUpperCase()}

                      </span>    } catch (error) {    } catch (error) {

                      <span className={`px-2 py-1 rounded-full text-xs font-medium ${getChangeTypeColor(alert.change)}`}>

                        {alert.change.toUpperCase()}      toast({      toast({

                      </span>

                    </div>        title: "Failed to Add Path",        title: "Failed to Add Path",

                    <p className="text-slate-400 mb-2">{alert.details}</p>

                    <div className="flex items-center space-x-4 text-sm text-slate-500">        description: error.message,        description: error.message,

                      <span>

                        <Clock className="w-3 h-3 inline mr-1" />        variant: "destructive"        variant: "destructive"

                        {alert.timestamp.toLocaleTimeString()}

                      </span>      });      });

                      <span>Status: <span className="font-medium text-slate-300">{alert.status}</span></span>

                    </div>    }    }

                  </div>

                  <div className="flex space-x-2">  };  };

                    <Button variant="outline" size="sm" onClick={() => handleAlertAction(alert.id, 'details')}>

                      <Eye className="w-4 h-4 mr-2" />

                      Details

                    </Button>  const startMonitoring = async () => {  const startMonitoring = async () => {

                    <Button variant="outline" size="sm" onClick={() => handleAlertAction(alert.id, 'resolve')}>

                      Resolve    try {    try {

                    </Button>

                  </div>      await apiClient.post('/fim/start');      await apiClient.post('/fim/start');

                </div>

              </motion.div>      setMonitoring(true);      setMonitoring(true);

            ))}

          </div>      toast({      toast({

        )}

      </motion.div>        title: "Monitoring Started",        title: "Monitoring Started",



      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.4 }} className="glass-card p-6 rounded-xl">        description: "File integrity monitoring is now active",        description: "File integrity monitoring is now active",

        <h2 className="text-xl font-semibold text-white mb-6 flex items-center">

          <FolderPlus className="w-5 h-5 mr-2 text-green-400" />      });      });

          Watched Paths ({watchedPaths.length})

        </h2>    } catch (error) {    } catch (error) {

        

        <div className="space-y-4">      toast({      toast({

          <div className="flex items-center space-x-4">

            <input        title: "Failed to Start Monitoring",        title: "Failed to Start Monitoring",

              type="text"

              value={newPath}        description: "Could not start file integrity monitoring",        description: "Could not start file integrity monitoring",

              onChange={(e) => setNewPath(e.target.value)}

              placeholder="Enter path to monitor (e.g., C:\Windows\System32)"        variant: "destructive"        variant: "destructive"

              className="flex-1 px-4 py-2 bg-slate-800/50 border border-slate-700 rounded-lg text-white placeholder:text-slate-400 focus:border-blue-500 focus:outline-none"

            />      });      });

            <Button onClick={addWatchPath} className="bg-green-600 hover:bg-green-700">

              <FolderPlus className="w-4 h-4 mr-2" />    }    }

              Add Path

            </Button>  };  };

          </div>



          {watchedPaths.length === 0 ? (

            <div className="text-center py-8 text-slate-400">  return (  return (

              <p>No paths are currently being monitored.</p>

              <p className="text-sm">Add paths above to start monitoring file integrity.</p>    <div className="space-y-6">    <div className="space-y-6">

            </div>

          ) : (      <motion.div initial={{ opacity: 0, y: -20 }} animate={{ opacity: 1, y: 0 }} className="flex items-center justify-between">      <motion.div initial={{ opacity: 0, y: -20 }} animate={{ opacity: 1, y: 0 }} className="flex items-center justify-between">

            <div className="space-y-2">

              {watchedPaths.map((path, index) => (        <div>        <div>

                <motion.div

                  key={path.id || index}          <h1 className="text-3xl font-bold text-white mb-2">File Integrity Monitoring</h1>          <h1 className="text-3xl font-bold text-white mb-2">File Integrity Monitoring</h1>

                  initial={{ opacity: 0, x: -20 }}

                  animate={{ opacity: 1, x: 0 }}          <p className="text-slate-400">Detect changes to critical system and application files.</p>          <p className="text-slate-400">Detect changes to critical system and application files.</p>

                  transition={{ delay: index * 0.1 }}

                  className="p-3 bg-slate-800/50 rounded-lg border border-slate-700/50 hover:border-slate-600/50 transition-all duration-200"        </div>        </div>

                >

                  <div className="flex items-center justify-between">        <Button variant="outline" size="sm" onClick={() => setAutoRefresh(!autoRefresh)} className={autoRefresh ? 'border-green-500 text-green-400' : 'border-slate-600 text-slate-400'}>        <Button variant="outline" size="sm" onClick={() => setAutoRefresh(!autoRefresh)} className={autoRefresh ? 'border-green-500 text-green-400' : 'border-slate-600 text-slate-400'}>

                    <div className="flex-1">

                      <span className="text-white font-mono text-sm">{path.path || path}</span>          <RefreshCw className={`w-4 h-4 mr-2 ${autoRefresh ? 'animate-spin' : ''}`} />          <RefreshCw className={`w-4 h-4 mr-2 ${autoRefresh ? 'animate-spin' : ''}`} />

                      <div className="text-xs text-slate-400 mt-1">

                        Added: {path.added ? new Date(path.added).toLocaleString() : 'Unknown'}          Auto Refresh          Auto Refresh

                      </div>

                    </div>        </Button>        </Button>

                    <div className="flex items-center space-x-2">

                      <span className={`px-2 py-1 rounded-full text-xs font-medium ${      </motion.div>      </motion.div>

                        path.active ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'

                      }`}>

                        {path.active ? 'Active' : 'Inactive'}

                      </span>      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }} className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }} className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">

                    </div>

                  </div>        <div className="glass-card p-6 rounded-xl">        <div className="glass-card p-6 rounded-xl">

                </motion.div>

              ))}          <div className="flex items-center justify-between mb-2">          <div className="flex items-center justify-between mb-2">

            </div>

          )}            <div className="w-12 h-12 bg-gradient-to-br from-red-500 to-red-600 rounded-lg flex items-center justify-center"><AlertTriangle className="w-6 h-6 text-white" /></div>            <div className="w-12 h-12 bg-gradient-to-br from-red-500 to-red-600 rounded-lg flex items-center justify-center"><AlertTriangle className="w-6 h-6 text-white" /></div>



          <div className="flex items-center justify-between pt-4 border-t border-slate-700">            <span className="text-2xl font-bold text-white">{fimAlerts.filter(a => a.severity === 'critical').length}</span>            <span className="text-2xl font-bold text-white">{fimAlerts.filter(a => a.severity === 'critical').length}</span>

            <div className="text-sm text-slate-400">

              Monitoring Status: {monitoring ? 'Active' : 'Inactive'}          </div>          </div>

            </div>

            <Button           <h3 className="text-sm text-slate-400">Critical Alerts</h3>          <h3 className="text-sm text-slate-400">Critical Alerts</h3>

              onClick={startMonitoring}

              disabled={monitoring}        </div>        </div>

              className={monitoring ? 'bg-gray-600' : 'bg-blue-600 hover:bg-blue-700'}

            >        <div className="glass-card p-6 rounded-xl">        <div className="glass-card p-6 rounded-xl">

              {monitoring ? 'Monitoring Active' : 'Start Monitoring'}

            </Button>          <div className="flex items-center justify-between mb-2">          <div className="flex items-center justify-between mb-2">

          </div>

        </div>            <div className="w-12 h-12 bg-gradient-to-br from-yellow-500 to-yellow-600 rounded-lg flex items-center justify-center"><FileCheck2 className="w-6 h-6 text-white" /></div>            <div className="w-12 h-12 bg-gradient-to-br from-yellow-500 to-yellow-600 rounded-lg flex items-center justify-center"><FileCheck2 className="w-6 h-6 text-white" /></div>

      </motion.div>

    </div>            <span className="text-2xl font-bold text-white">{fimAlerts.filter(a => a.change === 'Modified').length}</span>            <span className="text-2xl font-bold text-white">{fimAlerts.filter(a => a.change === 'Modified').length}</span>

  );

};          </div>          </div>



export default FileIntegrityMonitor;          <h3 className="text-sm text-slate-400">Files Modified</h3>          <h3 className="text-sm text-slate-400">Files Modified</h3>

        </div>        </div>

        <div className="glass-card p-6 rounded-xl">        <div className="glass-card p-6 rounded-xl">

          <div className="flex items-center justify-between mb-2">          <div className="flex items-center justify-between mb-2">

            <div className="w-12 h-12 bg-gradient-to-br from-green-500 to-green-600 rounded-lg flex items-center justify-center"><FileCheck2 className="w-6 h-6 text-white" /></div>            <div className="w-12 h-12 bg-gradient-to-br from-green-500 to-green-600 rounded-lg flex items-center justify-center"><FileCheck2 className="w-6 h-6 text-white" /></div>

            <span className="text-2xl font-bold text-white">{fimAlerts.filter(a => a.change === 'Added').length}</span>            <span className="text-2xl font-bold text-white">{fimAlerts.filter(a => a.change === 'Added').length}</span>

          </div>          </div>

          <h3 className="text-sm text-slate-400">Files Added</h3>          <h3 className="text-sm text-slate-400">Files Added</h3>

        </div>        </div>

        <div className="glass-card p-6 rounded-xl">        <div className="glass-card p-6 rounded-xl">

          <div className="flex items-center justify-between mb-2">          <div className="flex items-center justify-between mb-2">

            <div className="w-12 h-12 bg-gradient-to-br from-blue-500 to-blue-600 rounded-lg flex items-center justify-center"><CheckCircle className="w-6 h-6 text-white" /></div>            <div className="w-12 h-12 bg-gradient-to-br from-blue-500 to-blue-600 rounded-lg flex items-center justify-center"><CheckCircle className="w-6 h-6 text-white" /></div>

            <span className="text-2xl font-bold text-white">{fimAlerts.filter(a => a.status === 'resolved').length}</span>            <span className="text-2xl font-bold text-white">{fimAlerts.filter(a => a.status === 'resolved').length}</span>

          </div>          </div>

          <h3 className="text-sm text-slate-400">Alerts Resolved</h3>          <h3 className="text-sm text-slate-400">Alerts Resolved</h3>

        </div>        </div>

      </motion.div>      </motion.div>



      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }} className="glass-card p-6 rounded-xl">      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }} className="glass-card p-6 rounded-xl">

        <div className="flex items-center justify-between mb-4">        <div className="flex items-center justify-between mb-4">

          <h2 className="text-xl font-semibold text-white flex items-center"><Filter className="w-5 h-5 mr-2 text-blue-400" />Alert Filters</h2>          <h2 className="text-xl font-semibold text-white flex items-center"><Filter className="w-5 h-5 mr-2 text-blue-400" />Alert Filters</h2>

        </div>        </div>

        <div className="flex items-center space-x-4">        <div className="flex items-center space-x-4">

          <span className="text-sm text-slate-400">Filter by change type:</span>          <span className="text-sm text-slate-400">Filter by change type:</span>

          {['all', 'added', 'modified', 'deleted'].map((type) => (          {['all', 'added', 'modified', 'deleted'].map((type) => (

            <Button key={type} variant={filterType === type ? 'default' : 'outline'} size="sm" onClick={() => setFilterType(type)} className={filterType === type ? 'bg-blue-600' : 'border-slate-600 text-slate-400'}>            <Button key={type} variant={filterType === type ? 'default' : 'outline'} size="sm" onClick={() => setFilterType(type)} className={filterType === type ? 'bg-blue-600' : 'border-slate-600 text-slate-400'}>

              {type.charAt(0).toUpperCase() + type.slice(1)}              {type.charAt(0).toUpperCase() + type.slice(1)}

            </Button>            </Button>

          ))}          ))}

        </div>        </div>

      </motion.div>      </motion.div>



      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }} className="glass-card p-6 rounded-xl">      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }} className="glass-card p-6 rounded-xl">

        <h2 className="text-xl font-semibold text-white mb-6 flex items-center"><FileCheck2 className="w-5 h-5 mr-2 text-red-400" />FIM Alerts ({filteredAlerts.length})</h2>        <h2 className="text-xl font-semibold text-white mb-6 flex items-center"><FileCheck2 className="w-5 h-5 mr-2 text-red-400" />FIM Alerts ({filteredAlerts.length})</h2>

        {filteredAlerts.length === 0 ? (        {filteredAlerts.length === 0 ? (

          <div className="text-center py-8 text-slate-400">          <div className="text-center py-8 text-slate-400">

            <p>No file integrity alerts.</p>            <p>No file integrity alerts.</p>

            <p className="text-sm">The system is monitoring for file changes.</p>            <p className="text-sm">The system is monitoring for file changes.</p>

          </div>          </div>

        ) : (        ) : (

          <div className="space-y-4">          <div className="space-y-4">

            {filteredAlerts.map((alert, index) => (            {filteredAlerts.map((alert, index) => (

              <motion.div key={alert.id} initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: index * 0.1 }} className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50 hover:border-slate-600/50 transition-all duration-200">              <motion.div key={alert.id} initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: index * 0.1 }} className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50 hover:border-slate-600/50 transition-all duration-200">

                <div className="flex items-start justify-between">                <div className="flex items-start justify-between">

                  <div className="flex-1">                  <div className="flex-1">

                    <div className="flex items-center space-x-3 mb-2">                    <div className="flex items-center space-x-3 mb-2">

                      <h3 className="text-lg font-semibold text-white font-mono truncate">{alert.file}</h3>                      <h3 className="text-lg font-semibold text-white font-mono truncate">{alert.file}</h3>

                      <span className={`px-2 py-1 rounded-full text-xs font-medium border ${getSeverityColor(alert.severity)}`}>{alert.severity.toUpperCase()}</span>                      <span className={`px-2 py-1 rounded-full text-xs font-medium border ${getSeverityColor(alert.severity)}`}>{alert.severity.toUpperCase()}</span>

                      <span className={`px-2 py-1 rounded-full text-xs font-medium ${getChangeTypeColor(alert.change)}`}>{alert.change.toUpperCase()}</span>                      <span className={`px-2 py-1 rounded-full text-xs font-medium ${getChangeTypeColor(alert.change)}`}>{alert.change.toUpperCase()}</span>

                    </div>                    </div>

                    <p className="text-slate-400 mb-2">{alert.details}</p>                    <p className="text-slate-400 mb-2">{alert.details}</p>

                    <div className="flex items-center space-x-4 text-sm text-slate-500">                    <div className="flex items-center space-x-4 text-sm text-slate-500">

                      <span><Clock className="w-3 h-3 inline mr-1" />{alert.timestamp.toLocaleTimeString()}</span>                      <span><Clock className="w-3 h-3 inline mr-1" />{alert.timestamp.toLocaleTimeString()}</span>

                      <span>Status: <span className="font-medium text-slate-300">{alert.status}</span></span>                      <span>Status: <span className="font-medium text-slate-300">{alert.status}</span></span>

                    </div>                    </div>

                  </div>                  </div>

                  <div className="flex space-x-2">                  <div className="flex space-x-2">

                    <Button variant="outline" size="sm" onClick={() => handleAlertAction(alert.id, 'details')}><Eye className="w-4 h-4 mr-2" />Details</Button>                    <Button variant="outline" size="sm" onClick={() => handleAlertAction(alert.id, 'details')}><Eye className="w-4 h-4 mr-2" />Details</Button>

                    <Button variant="outline" size="sm" onClick={() => handleAlertAction(alert.id, 'resolve')}>Resolve</Button>                    <Button variant="outline" size="sm" onClick={() => handleAlertAction(alert.id, 'resolve')}>Resolve</Button>

                  </div>                  </div>

                </div>                </div>

              </motion.div>              </motion.div>

            ))}            ))}

          </div>          </div>

        )}        )}

      </motion.div>      </motion.div>



      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.4 }} className="glass-card p-6 rounded-xl">      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.4 }} className="glass-card p-6 rounded-xl">

        <h2 className="text-xl font-semibold text-white mb-6 flex items-center">        <h2 className="text-xl font-semibold text-white mb-6 flex items-center">

          <FolderPlus className="w-5 h-5 mr-2 text-green-400" />          <FolderPlus className="w-5 h-5 mr-2 text-green-400" />

          Watched Paths ({watchedPaths.length})          Watched Paths ({watchedPaths.length})

        </h2>        </h2>

                

        <div className="space-y-4">        <div className="space-y-4">

          <div className="flex items-center space-x-4">          <div className="flex items-center space-x-4">

            <input            <input

              type="text"              type="text"

              value={newPath}              value={newPath}

              onChange={(e) => setNewPath(e.target.value)}              onChange={(e) => setNewPath(e.target.value)}

              placeholder="Enter path to monitor (e.g., C:\Windows\System32)"              placeholder="Enter path to monitor (e.g., C:\Windows\System32)"

              className="flex-1 px-4 py-2 bg-slate-800/50 border border-slate-700 rounded-lg text-white placeholder:text-slate-400 focus:border-blue-500 focus:outline-none"              className="flex-1 px-4 py-2 bg-slate-800/50 border border-slate-700 rounded-lg text-white placeholder:text-slate-400 focus:border-blue-500 focus:outline-none"

            />            />

            <Button onClick={addWatchPath} className="bg-green-600 hover:bg-green-700">            <Button onClick={addWatchPath} className="bg-green-600 hover:bg-green-700">

              <FolderPlus className="w-4 h-4 mr-2" />              <FolderPlus className="w-4 h-4 mr-2" />

              Add Path              Add Path

            </Button>            </Button>

          </div>          </div>



          {watchedPaths.length === 0 ? (          {watchedPaths.length === 0 ? (

            <div className="text-center py-8 text-slate-400">            <div className="text-center py-8 text-slate-400">

              <p>No paths are currently being monitored.</p>              <p>No paths are currently being monitored.</p>

              <p className="text-sm">Add paths above to start monitoring file integrity.</p>              <p className="text-sm">Add paths above to start monitoring file integrity.</p>

            </div>            </div>

          ) : (          ) : (

            <div className="space-y-2">            <div className="space-y-2">

              {watchedPaths.map((path, index) => (              {watchedPaths.map((path, index) => (

                <motion.div                <motion.div

                  key={path.id || index}                  key={path.id || index}

                  initial={{ opacity: 0, x: -20 }}                  initial={{ opacity: 0, x: -20 }}

                  animate={{ opacity: 1, x: 0 }}                  animate={{ opacity: 1, x: 0 }}

                  transition={{ delay: index * 0.1 }}                  transition={{ delay: index * 0.1 }}

                  className="p-3 bg-slate-800/50 rounded-lg border border-slate-700/50 hover:border-slate-600/50 transition-all duration-200"                  className="p-3 bg-slate-800/50 rounded-lg border border-slate-700/50 hover:border-slate-600/50 transition-all duration-200"

                >                >

                  <div className="flex items-center justify-between">                  <div className="flex items-center justify-between">

                    <div className="flex-1">                    <div className="flex-1">

                      <span className="text-white font-mono text-sm">{path.path || path}</span>                      <span className="text-white font-mono text-sm">{path.path || path}</span>

                      <div className="text-xs text-slate-400 mt-1">                      <div className="text-xs text-slate-400 mt-1">

                        Added: {path.added ? new Date(path.added).toLocaleString() : 'Unknown'}                        Added: {path.added ? new Date(path.added).toLocaleString() : 'Unknown'}

                      </div>                      </div>

                    </div>                    </div>

                    <div className="flex items-center space-x-2">                    <div className="flex items-center space-x-2">

                      <span className={`px-2 py-1 rounded-full text-xs font-medium ${                      <span className={`px-2 py-1 rounded-full text-xs font-medium ${

                        path.active ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'                        path.active ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'

                      }`}>                      }`}>

                        {path.active ? 'Active' : 'Inactive'}                        {path.active ? 'Active' : 'Inactive'}

                      </span>                      </span>

                    </div>                    </div>

                  </div>                  </div>

                </motion.div>                </motion.div>

              ))}              ))}

            </div>            </div>

          )}          )}



          <div className="flex items-center justify-between pt-4 border-t border-slate-700">          <div className="flex items-center justify-between pt-4 border-t border-slate-700">

            <div className="text-sm text-slate-400">            <div className="text-sm text-slate-400">

              Monitoring Status: {monitoring ? 'Active' : 'Inactive'}              Monitoring Status: {monitoring ? 'Active' : 'Inactive'}

            </div>            </div>

            <Button             <Button 

              onClick={startMonitoring}              onClick={startMonitoring}

              disabled={monitoring}              disabled={monitoring}

              className={monitoring ? 'bg-gray-600' : 'bg-blue-600 hover:bg-blue-700'}              className={monitoring ? 'bg-gray-600' : 'bg-blue-600 hover:bg-blue-700'}

            >            >

              {monitoring ? 'Monitoring Active' : 'Start Monitoring'}              {monitoring ? 'Monitoring Active' : 'Start Monitoring'}

            </Button>            </Button>

          </div>          </div>

        </div>        </div>

      </motion.div>      </motion.div>

    </div>    </div>

  );  );

};};



export default FileIntegrityMonitor;export default FileIntegrityMonitor;