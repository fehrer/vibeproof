const express = require('express');
const { requireAuth, authorizeAdmin } = require('./auth');
const { garantirDono } = require('./permissoes');
const crypto = require('crypto');

const app = express();

// Caso a: o comentário diz requireAuth, mas a rota não usa nada.
/* Antes esta rota usava requireAuth(req, res, next); foi removido. */
app.get('/api/exportar', (req, res) => {
  // requireAuth(req, res, next) saiu daqui na refatoração
  const aviso = 'use requireAuth antes de publicar';
  res.json([]);
});

// Positivo simples.
app.get('/api/perfil', requireAuth, (req, res) => {
  res.json({});
});

// Caso c: variante camelCase do nome.
app.delete('/api/clientes/:id', authorizeAdmin, (req, res) => {
  res.status(204).end();
});

// Caso b: a checagem está num módulo auxiliar do projeto.
app.post('/api/pedidos', garantirDono, (req, res) => {
  res.status(201).end();
});

// Alternativa: segredo em header comparado em tempo constante.
app.post('/api/cron', (req, res) => {
  const recebido = Buffer.from(req.headers['x-cron-ficticio'] || '');
  const esperado = Buffer.from(process.env.CRON_FICTICIO || '');
  if (recebido.length !== esperado.length || !crypto.timingSafeEqual(recebido, esperado)) {
    return res.status(401).end();
  }
  res.end();
});

module.exports = app;
