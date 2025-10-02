// API client with request deduplication and proper error handling
class APIClient {
  constructor() {
    this.pendingRequests = new Map();
    // Use import.meta.env for Vite instead of process.env
    this.API_BASE_URL = import.meta.env.VITE_API_BASE || 'http://localhost:3001/api';
  }

  // Create a cache key for request deduplication
  createCacheKey(url, options = {}) {
    const method = options.method || 'GET';
    const body = options.body || '';
    return `${method}:${url}:${body}`;
  }

  // Fetch with automatic deduplication
  async fetch(endpoint, options = {}) {
    const url = `${this.API_BASE_URL}${endpoint}`;
    const cacheKey = this.createCacheKey(url, options);

    // If request is already pending, return the existing promise
    if (this.pendingRequests.has(cacheKey)) {
      console.log(`Deduplicating request: ${cacheKey}`);
      return this.pendingRequests.get(cacheKey);
    }

    // Create abort controller for cancellation
    const controller = new AbortController();
    const requestOptions = {
      ...options,
      signal: controller.signal,
      headers: {
        'Content-Type': 'application/json',
        ...options.headers,
      },
    };

    // Create the request promise
    const requestPromise = fetch(url, requestOptions)
      .then(async (response) => {
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        return response.json();
      })
      .catch((error) => {
        if (error.name === 'AbortError') {
          console.log(`Request cancelled: ${cacheKey}`);
        } else {
          console.error(`Request failed: ${cacheKey}`, error);
        }
        throw error;
      })
      .finally(() => {
        // Remove from pending requests when complete
        this.pendingRequests.delete(cacheKey);
      });

    // Store the promise with its controller
    requestPromise.controller = controller;
    this.pendingRequests.set(cacheKey, requestPromise);

    return requestPromise;
  }

  // Cancel all pending requests
  cancelAllRequests() {
    for (const [key, request] of this.pendingRequests) {
      if (request.controller) {
        request.controller.abort();
      }
    }
    this.pendingRequests.clear();
  }

  // Cancel specific request
  cancelRequest(endpoint, options = {}) {
    const url = `${this.baseURL}${endpoint}`;
    const cacheKey = this.createCacheKey(url, options);
    const request = this.pendingRequests.get(cacheKey);
    
    if (request && request.controller) {
      request.controller.abort();
      this.pendingRequests.delete(cacheKey);
    }
  }

  // Common API methods with deduplication
  async get(endpoint) {
    return this.fetch(endpoint, { method: 'GET' });
  }

  async post(endpoint, data) {
    return this.fetch(endpoint, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async put(endpoint, data) {
    return this.fetch(endpoint, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  }

  async delete(endpoint) {
    return this.fetch(endpoint, { method: 'DELETE' });
  }
}

// Export singleton instance
export const apiClient = new APIClient();
export default apiClient;