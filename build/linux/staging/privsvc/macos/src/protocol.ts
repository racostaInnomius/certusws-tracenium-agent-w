export type PrivSvcRequest = {
  v: number;
  id: string;
  method: string;
  params?: Record<string, any>;
  meta?: {
    tenantId?: string;
    deviceId?: string;
    traceId?: string;
  };
};

export type PrivSvcResponse =
  | { v: 1; id: string; ok: true; result: any; error: null }
  | { v: 1; id: string; ok: false; result: null; error: { code: string; message: string } };

export type PushSink = (msg: Record<string, any>) => void;

export function success(id: string, result: any): PrivSvcResponse {
  return { v: 1, id, ok: true, result, error: null };
}

export function fail(id: string, code: string, message: string): PrivSvcResponse {
  return { v: 1, id: id || "unknown", ok: false, result: null, error: { code, message } };
}
