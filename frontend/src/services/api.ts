/**
 * NiksES API Service
 * 
 * Axios instance configuration and base API utilities.
 */

import axios, { AxiosInstance, AxiosError, AxiosRequestConfig } from 'axios';
import { API_BASE_URL, API_TIMEOUT } from '../utils/constants';
import type { APIError } from '../types/api';

/**
 * Create configured Axios instance
 */
const createApiClient = (): AxiosInstance => {
  const instance = axios.create({
    baseURL: API_BASE_URL,
    timeout: API_TIMEOUT,
    headers: {
      'Content-Type': 'application/json',
    },
  });

  // Request interceptor
  instance.interceptors.request.use(
    (config) => {
      // Add any auth tokens here if needed
      return config;
    },
    (error) => {
      return Promise.reject(error);
    }
  );

  // Response interceptor
  instance.interceptors.response.use(
    (response) => response,
    (error: AxiosError<{ detail?: string; message?: string }>) => {
      const apiError: APIError = {
        status: error.response?.status || 500,
        message: error.response?.data?.message || error.response?.data?.detail || error.message,
        detail: error.response?.data?.detail,
      };
      return Promise.reject(apiError);
    }
  );

  return instance;
};

export const apiClient = createApiClient();

/**
 * Generic GET request
 */
export async function get<T>(url: string, config?: AxiosRequestConfig): Promise<T> {
  const response = await apiClient.get<T>(url, config);
  return response.data;
}

/**
 * Generic POST request
 */
export async function post<T>(
  url: string,
  data?: unknown,
  config?: AxiosRequestConfig
): Promise<T> {
  const response = await apiClient.post<T>(url, data, config);
  return response.data;
}

/**
 * Generic PUT request
 */
export async function put<T>(
  url: string,
  data?: unknown,
  config?: AxiosRequestConfig
): Promise<T> {
  const response = await apiClient.put<T>(url, data, config);
  return response.data;
}

/**
 * Generic DELETE request
 */
export async function del<T>(url: string, config?: AxiosRequestConfig): Promise<T> {
  const response = await apiClient.delete<T>(url, config);
  return response.data;
}

/**
 * Upload file with multipart form data
 */
export async function uploadFile<T>(
  url: string,
  file: File,
  additionalData?: Record<string, string>,
  onProgress?: (progress: number) => void
): Promise<T> {
  const formData = new FormData();
  formData.append('file', file);

  if (additionalData) {
    Object.entries(additionalData).forEach(([key, value]) => {
      formData.append(key, value);
    });
  }

  const response = await apiClient.post<T>(url, formData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
    onUploadProgress: (progressEvent) => {
      if (onProgress && progressEvent.total) {
        const progress = Math.round((progressEvent.loaded * 100) / progressEvent.total);
        onProgress(progress);
      }
    },
  });

  return response.data;
}

/**
 * Download file as blob
 */
export async function downloadBlob(url: string, params?: Record<string, string>): Promise<Blob> {
  const response = await apiClient.get(url, {
    params,
    responseType: 'blob',
  });
  return response.data;
}

export default apiClient;
