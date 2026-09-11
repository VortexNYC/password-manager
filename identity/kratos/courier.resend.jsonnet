function(ctx) {
  from: 'Veil <noreply@veil.nyc>',
  to: [ctx.recipient],
  subject: ctx.subject,
  html: ctx.body,
}
