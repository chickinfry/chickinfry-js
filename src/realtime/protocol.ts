const uuid = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;
const encoder = new TextEncoder();
const maxChannelBytes = 128;
const maxFrameBytes = 66560;

export interface RealtimeEventFrame {
  readonly type: "event";
  readonly channel: string;
  readonly cursor: string;
  readonly previous: string;
  readonly payload: unknown;
}

export interface RealtimeGapFrame {
  readonly type: "gap";
  readonly channel: string;
  readonly cursor: string;
}

export interface RealtimeErrorFrame {
  readonly type: "error";
  readonly error: string;
  readonly channel?: string;
}

export interface RealtimeReadyFrame {
  readonly type: "ready";
  readonly channel: string;
  readonly cursor: string;
  readonly acknowledge?: boolean;
  readonly confirmation?: string;
}

export type RealtimeServerFrame = RealtimeEventFrame | RealtimeGapFrame | RealtimeErrorFrame | RealtimeReadyFrame;

export interface RealtimeSubscribeFrame {
  readonly type: "subscribe";
  readonly channel: string;
  readonly cursor?: string;
  readonly subscription?: string;
}

export interface RealtimeAcknowledgmentFrame {
  readonly type: "ack";
  readonly channel: string;
  readonly cursor: string;
}

export interface RealtimeUnsubscribeFrame {
  readonly type: "unsubscribe";
  readonly channel: string;
}

export interface RealtimeConfirmFrame {
  readonly type: "confirm";
  readonly channel: string;
  readonly confirmation?: string;
}

export type RealtimeClientFrame = RealtimeSubscribeFrame | RealtimeUnsubscribeFrame | RealtimeAcknowledgmentFrame | RealtimeConfirmFrame;

export function validConfirmation(value: unknown): value is string {
  return typeof value === "string" && uuid.test(value);
}

export function validChannel(value: unknown): value is string {
  if (typeof value !== "string" || value.length === 0 || encoder.encode(value).length > maxChannelBytes) return false;
  return !/[\u0000-\u001f\u007f]/u.test(value) && new TextDecoder().decode(encoder.encode(value)) === value;
}

export function validCursor(value: unknown): value is string {
  return typeof value === "string" && (value === "" || uuid.test(value));
}

export function encodeFrame(frame: RealtimeServerFrame | RealtimeClientFrame): string {
  const text = JSON.stringify(frame);
  if (encoder.encode(text).length > maxFrameBytes) throw new Error("Realtime frame is too large.");
  return text;
}

export function parseClientFrame(text: string): RealtimeClientFrame | undefined {
  if (encoder.encode(text).length > maxFrameBytes) return undefined;
  return parse(text, value => {
    if (typeof value !== "object" || value === null) return false;
    const frame = value as Record<string, unknown>;
    if (frame.type === "subscribe") {
      return validChannel(frame.channel) && (frame.cursor === undefined || validCursor(frame.cursor)) &&
        (frame.subscription === undefined || (typeof frame.subscription === "string" && uuid.test(frame.subscription)));
    }
    if(frame.type === "ack") return validChannel(frame.channel) && validCursor(frame.cursor);
    if(frame.type === "confirm") return validChannel(frame.channel) &&
      (frame.confirmation === undefined || validConfirmation(frame.confirmation));
    return frame.type === "unsubscribe" && validChannel(frame.channel);
  }) as RealtimeClientFrame | undefined;
}

export function parseServerFrame(text: string): RealtimeServerFrame | undefined {
  if (encoder.encode(text).length > maxFrameBytes) return undefined;
  return parse(text, value => {
    if (typeof value !== "object" || value === null) return false;
    const frame = value as Record<string, unknown>;
    if (frame.type === "event") {
      return validChannel(frame.channel) && typeof frame.cursor === "string" && uuid.test(frame.cursor) &&
        typeof frame.previous === "string" && (frame.previous === "" || uuid.test(frame.previous)) &&
        "payload" in frame;
    }
    if (frame.type === "gap") {
      return validChannel(frame.channel) && validCursor(frame.cursor);
    }
    if (frame.type === "ready") return validChannel(frame.channel) && validCursor(frame.cursor) &&
      (frame.acknowledge === undefined || typeof frame.acknowledge === "boolean") &&
      (frame.confirmation === undefined || validConfirmation(frame.confirmation));
    return frame.type === "error" && typeof frame.error === "string" && /^[a-z_]{1,64}$/u.test(frame.error) &&
      (frame.channel === undefined || validChannel(frame.channel));
  }) as RealtimeServerFrame | undefined;
}

function parse<T>(text: string, check: (value: unknown) => boolean): T | undefined {
  let value: unknown;
  try { value = JSON.parse(text); }
  catch { return undefined; }
  return check(value) ? value as T : undefined;
}
