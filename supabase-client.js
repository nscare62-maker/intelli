/**
 * ==========================================================
 * Project 26-78: Blockchain Enabled Secure IoT Communication
 * Supabase Integration Service (supabase-client.js)
 * ==========================================================
 */

const SupabaseService = {
  client: null,
  isConfigured: false,
  isConnected: false,
  realtimeSubscription: null,

  // Default credentials (can be stored in localStorage or hardcoded here)
  config: {
    url: localStorage.getItem('PROJECT_SUPABASE_URL') || 'https://onijcokovgebfxjzrpne.supabase.co',
    anonKey: localStorage.getItem('PROJECT_SUPABASE_KEY') || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im9uaWpjb2tvdmdlYmZ4anpycG5lIiwicm9sZSI6ImFub24iLCJpYXQiOjE3OTMyNjI0MTcsImV4cCI6MjEwODgzODQxN30.mUKScQvbvwWArpIwQhJLIHdh9p6cbxsKAz3JddVRUqM'
  },

  /**
   * Initialize Supabase client
   */
  init: async function() {
    this.config.url = localStorage.getItem('PROJECT_SUPABASE_URL') || this.config.url;
    this.config.anonKey = localStorage.getItem('PROJECT_SUPABASE_KEY') || this.config.anonKey;

    if (!window.supabase || !this.config.url || !this.config.anonKey) {
      this.isConfigured = false;
      this.isConnected = false;
      this.updateUIStatus();
      return false;
    }

    try {
      this.client = window.supabase.createClient(this.config.url, this.config.anonKey);
      this.isConfigured = true;

      // Test connection
      const test = await this.testConnection();
      this.isConnected = test.success;
      this.updateUIStatus();

      if (this.isConnected) {
        this.setupRealtimeListeners();
      }

      return this.isConnected;
    } catch (err) {
      console.warn('[Supabase] Initialization failed, using local in-memory fallback:', err);
      this.isConfigured = false;
      this.isConnected = false;
      this.updateUIStatus();
      return false;
    }
  },

  /**
   * Save credentials from modal and reconnect
   */
  saveCredentials: async function(url, anonKey) {
    url = (url || '').trim();
    anonKey = (anonKey || '').trim();

    if (!url || !anonKey) {
      throw new Error('Please provide both Project URL and Anon Key.');
    }

    if (!url.startsWith('https://')) {
      throw new Error('Supabase URL must start with https://');
    }

    localStorage.setItem('PROJECT_SUPABASE_URL', url);
    localStorage.setItem('PROJECT_SUPABASE_KEY', anonKey);
    this.config.url = url;
    this.config.anonKey = anonKey;

    return await this.init();
  },

  /**
   * Disconnect and clear credentials
   */
  disconnect: function() {
    localStorage.removeItem('PROJECT_SUPABASE_URL');
    localStorage.removeItem('PROJECT_SUPABASE_KEY');
    this.config.url = '';
    this.config.anonKey = '';
    this.client = null;
    this.isConfigured = false;
    this.isConnected = false;
    if (this.realtimeSubscription) {
      this.client?.removeChannel?.(this.realtimeSubscription);
      this.realtimeSubscription = null;
    }
    this.updateUIStatus();
  },

  /**
   * Test connection to the database
   */
  testConnection: async function() {
    if (!this.client) return { success: false, error: 'Client not initialized' };

    try {
      const { data, error } = await this.client
        .from('iot_nodes')
        .select('id')
        .limit(1);

      if (error) {
        return { success: false, error: error.message };
      }

      return { success: true, count: data ? data.length : 0 };
    } catch (err) {
      return { success: false, error: err.message || 'Network connection failed' };
    }
  },

  /**
   * Update UI badge in top navbar
   */
  updateUIStatus: function() {
    const dot = document.getElementById('supabaseStatusDot');
    const text = document.getElementById('supabaseStatusText');

    if (!dot || !text) return;

    if (this.isConnected) {
      dot.className = 'w-2 h-2 rounded-full bg-emerald-500 shadow-sm animate-pulse';
      text.textContent = 'Supabase: Connected';
      text.className = 'text-emerald-400 font-medium hidden sm:inline';
    } else if (this.isConfigured) {
      dot.className = 'w-2 h-2 rounded-full bg-amber-500';
      text.textContent = 'Supabase: Error';
      text.className = 'text-amber-400 font-medium hidden sm:inline';
    } else {
      dot.className = 'w-2 h-2 rounded-full bg-slate-500';
      text.textContent = 'Connect DB';
      text.className = 'text-slate-400 font-medium hidden sm:inline';
    }
  },

  // ==========================================================
  // DATA ACCESS: IOT NODES
  // ==========================================================

  fetchNodes: async function() {
    if (!this.isConnected) return null;
    try {
      const { data, error } = await this.client
        .from('iot_nodes')
        .select('*')
        .order('id', { ascending: true });

      if (error) throw error;
      if (!data || data.length === 0) return [];

      // Map back to dashboard node object
      return data.map(row => ({
        id: row.id,
        name: row.name,
        type: row.type,
        mac: row.mac,
        protocol: row.protocol || 'MQTT',
        trustScore: row.trust_score ?? 95,
        status: row.status || 'Verified',
        lastSeen: row.last_seen || 'Just now',
        anomalyScore: row.anomaly_score ? parseFloat(row.anomaly_score) : 0.05
      }));
    } catch (err) {
      console.error('[Supabase] Failed to fetch nodes:', err);
      return null;
    }
  },

  upsertNode: async function(node) {
    if (!this.isConnected) return false;
    try {
      const row = {
        id: node.id,
        name: node.name,
        type: node.type,
        mac: node.mac,
        protocol: node.protocol || 'MQTT',
        trust_score: node.trustScore !== undefined ? node.trustScore : 95,
        status: node.status || 'Verified',
        last_seen: node.lastSeen || 'Just now',
        anomaly_score: node.anomalyScore || 0.05,
        updated_at: new Date().toISOString()
      };

      const { error } = await this.client
        .from('iot_nodes')
        .upsert(row, { onConflict: 'id' });

      if (error) throw error;
      return true;
    } catch (err) {
      console.error('[Supabase] Failed to upsert node:', err);
      return false;
    }
  },

  batchUpsertNodes: async function(nodesArray) {
    if (!this.isConnected || !nodesArray.length) return false;
    try {
      const rows = nodesArray.map(node => ({
        id: node.id,
        name: node.name,
        type: node.type,
        mac: node.mac,
        protocol: node.protocol || 'MQTT',
        trust_score: node.trustScore !== undefined ? node.trustScore : 95,
        status: node.status || 'Verified',
        last_seen: node.lastSeen || 'Just now',
        anomaly_score: node.anomalyScore || 0.05,
        updated_at: new Date().toISOString()
      }));

      const { error } = await this.client
        .from('iot_nodes')
        .upsert(rows, { onConflict: 'id' });

      if (error) throw error;
      return true;
    } catch (err) {
      console.error('[Supabase] Failed batch upsert nodes:', err);
      return false;
    }
  },

  updateNodeStatus: async function(nodeId, newStatus, newTrustScore) {
    if (!this.isConnected) return false;
    try {
      const updatePayload = {
        status: newStatus,
        updated_at: new Date().toISOString()
      };
      if (newTrustScore !== undefined) {
        updatePayload.trust_score = newTrustScore;
      }

      const { error } = await this.client
        .from('iot_nodes')
        .update(updatePayload)
        .eq('id', nodeId);

      if (error) throw error;
      return true;
    } catch (err) {
      console.error(`[Supabase] Failed to update node ${nodeId}:`, err);
      return false;
    }
  },

  // ==========================================================
  // DATA ACCESS: BLOCKCHAIN LEDGER
  // ==========================================================

  fetchBlocks: async function() {
    if (!this.isConnected) return null;
    try {
      const { data, error } = await this.client
        .from('blockchain_ledger')
        .select('*')
        .order('block_index', { ascending: true });

      if (error) throw error;
      if (!data || data.length === 0) return [];

      return data.map(row => ({
        index: row.block_index,
        timestamp: row.timestamp,
        deviceId: row.device_id,
        action: row.action,
        validator: row.validator,
        payload: row.payload,
        previousHash: row.previous_hash,
        hash: row.hash,
        nonce: row.nonce
      }));
    } catch (err) {
      console.error('[Supabase] Failed to fetch blocks:', err);
      return null;
    }
  },

  insertBlock: async function(block) {
    if (!this.isConnected) return false;
    try {
      const row = {
        block_index: block.index,
        timestamp: block.timestamp,
        device_id: block.deviceId,
        action: block.action,
        validator: block.validator,
        payload: block.payload || {},
        previous_hash: block.previousHash,
        hash: block.hash,
        nonce: block.nonce
      };

      const { error } = await this.client
        .from('blockchain_ledger')
        .upsert(row, { onConflict: 'block_index' });

      if (error) throw error;
      return true;
    } catch (err) {
      console.error('[Supabase] Failed to insert block:', err);
      return false;
    }
  },

  // ==========================================================
  // DATA ACCESS: TELEMETRY & SECURITY LOGS
  // ==========================================================

  insertLog: async function(level, source, message, details = {}) {
    if (!this.isConnected) return false;
    try {
      const row = {
        timestamp: new Date().toISOString(),
        level: level.toUpperCase(),
        source: source,
        message: message,
        details: typeof details === 'string' ? details : JSON.stringify(details)
      };

      const { error } = await this.client
        .from('telemetry_logs')
        .insert([row]);

      if (error) throw error;
      return true;
    } catch (err) {
      console.error('[Supabase] Failed to insert log:', err);
      return false;
    }
  },

  // ==========================================================
  // REALTIME WEBSOCKET SUBSCRIPTIONS
  // ==========================================================

  setupRealtimeListeners: function() {
    if (!this.client) return;

    try {
      const channel = this.client
        .channel('schema-db-changes')
        .on(
          'postgres_changes',
          { event: '*', schema: 'public', table: 'iot_nodes' },
          (payload) => {
            console.log('[Supabase Realtime] Node changed:', payload);
            if (window.handleSupabaseNodeChange) {
              window.handleSupabaseNodeChange(payload);
            }
          }
        )
        .on(
          'postgres_changes',
          { event: 'INSERT', schema: 'public', table: 'blockchain_ledger' },
          (payload) => {
            console.log('[Supabase Realtime] Block mined:', payload);
            if (window.handleSupabaseBlockChange) {
              window.handleSupabaseBlockChange(payload);
            }
          }
        )
        .subscribe();

      this.realtimeSubscription = channel;
    } catch (err) {
      console.warn('[Supabase Realtime] Could not subscribe:', err);
    }
  }
};

window.SupabaseService = SupabaseService;

