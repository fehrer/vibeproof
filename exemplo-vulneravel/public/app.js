import OpenAI from 'openai';

const openai = new OpenAI({ apiKey: import.meta.env.VITE_OPENAI_API_KEY, dangerouslyAllowBrowser: true });

export async function mostrarComentarios() {
  const res = await fetch('/api/comments');
  const comentarios = await res.json();
  const lista = document.querySelector('#comentarios');
  for (const c of comentarios) {
    lista.innerHTML += `<li><b>${c.autor}</b>: ${c.texto}</li>`;
  }
}

export async function resumir(texto) {
  const r = await openai.chat.completions.create({
    model: 'gpt-4o-mini',
    messages: [{ role: 'system', content: `Resuma para o usuário ${texto}` }],
  });
  document.querySelector('#resumo').innerHTML = r.choices[0].message.content;
}
