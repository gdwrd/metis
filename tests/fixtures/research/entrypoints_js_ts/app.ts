function show(req, res) {
  return res.send(req.query.id);
}

function fastifyShow(request, reply) {
  return reply.send(request.query.id);
}

function koaShow(ctx) {
  return ctx.query.id;
}

app.get('/users/:id', show);
fastify.route({ method: 'GET', url: '/fast/:id', handler: fastifyShow });
router.use('/koa/:id', koaShow);

@Get('/nest/:id')
function nestShow(req) {
  return req.query.id;
}
