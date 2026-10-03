const { createInterface } = require('node:readline');

const pendingDiagnosis = new Map();

createInterface({ input: process.stdin, crlfDelay: Infinity })
  .on('line', line => {
    let event;
    try {
      event = JSON.parse(line.replace(/^\d{4}-\d{2}-\d{2}T\S+\s+(?=\{)/, ''));
    } catch {
      console.log(line);
      return;
    }

    const data = event.data;
    if (event.type === 'assistant.message' && data?.content) {
      console.log(data.content);
    } else if (event.type === 'tool.execution_start' &&
               data?.toolName === 'apply_patch' &&
               typeof data.arguments === 'string' &&
               data.arguments.includes('copilot-diagnosis.md')) {
      pendingDiagnosis.set(data.toolCallId, data.arguments);
    } else if (event.type === 'tool.execution_complete') {
      const patch = pendingDiagnosis.get(data?.toolCallId);
      if (patch && data.success)
        console.log(`Diagnosis checkpoint:\n${patch}`);
      pendingDiagnosis.delete(data?.toolCallId);
      if (data?.success === false) {
        const details = String(data.result?.content ?? '').slice(0, 3000);
        console.log(`Tool ${data.toolCallId} failed: ${details}`);
      }
    }
  });
