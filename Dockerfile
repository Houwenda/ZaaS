FROM blacktop/zeek:3.0.12
COPY ./zaas /usr/local/bin/zaas
RUN chmod +x /usr/local/bin/zaas
EXPOSE 8000 
ENTRYPOINT []
CMD ["/usr/local/bin/zaas"]