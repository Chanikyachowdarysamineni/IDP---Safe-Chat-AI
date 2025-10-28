declare module '@huggingface/transformers' {
  // Minimal declaration for pipeline helper used in the app.
  export function pipeline(task: string, model?: string, options?: any): Promise<any>;
}
