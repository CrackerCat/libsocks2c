-- Drop table

-- DROP TABLE public.user_info;

CREATE TABLE public.user_info (
	uid int8 NOT NULL,
	username text NOT NULL,
	"password" text NOT NULL,
	isban bool NOT NULL,
	port int2 NOT NULL,
	"group" int8 NULL,
	CONSTRAINT user_info_pk PRIMARY KEY (uid),
	CONSTRAINT user_info_un UNIQUE (port)
);
