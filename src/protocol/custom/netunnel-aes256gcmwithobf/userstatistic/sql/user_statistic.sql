-- Drop table

-- DROP TABLE public.user_statistic;

CREATE TABLE public.user_statistic (
	uid int8 NOT NULL,
	src_host text NOT NULL,
	dst_host text NOT NULL,
	last_active_time timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	upstream_traffic varchar NOT NULL,
	downstream_traffic int8 NOT NULL,
	"type" text NOT NULL,
	CONSTRAINT user_statistic_fk FOREIGN KEY (uid) REFERENCES user_info(uid)
);
