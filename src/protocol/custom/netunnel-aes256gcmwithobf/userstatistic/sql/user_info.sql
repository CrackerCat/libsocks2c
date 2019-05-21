-- Drop table

-- DROP TABLE public.user_info;

CREATE SEQUENCE public.UID_SEQ
	INCREMENT BY 1
	MINVALUE 1
	MAXVALUE 9223372036854775807
	CACHE 1
	NO CYCLE;

CREATE SEQUENCE public.PORT_SEQ
	INCREMENT BY 2
	MINVALUE 10000
	MAXVALUE 65535
	CACHE 1
	NO CYCLE;


CREATE TABLE public.user_info (
  uid int8 NOT NULL DEFAULT nextval('UID_SEQ'),
  username text NOT NULL,
  password text NOT NULL,
  isban bool NOT NULL DEFAULT false,
  port int2 NOT NULL DEFAULT nextval('PORT_SEQ'),
  raw_port int2 NOT NULL,
  usergroup text NOT NULL,
  CONSTRAINT user_info_pk PRIMARY KEY (uid),
  CONSTRAINT user_info_un UNIQUE (port, raw_port)
);


