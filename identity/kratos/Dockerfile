FROM oryd/kratos:v26.2.0
COPY identity/kratos/kratos.veil.yml /etc/config/kratos/kratos.yml
COPY identity/kratos/identity.schema.json /etc/config/kratos/identity.schema.json
COPY identity/kratos/courier.resend.jsonnet /etc/config/kratos/courier.resend.jsonnet
CMD ["serve", "-c", "/etc/config/kratos/kratos.yml", "--sqa-opt-out", "--watch-courier"]
