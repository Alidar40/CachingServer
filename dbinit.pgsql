--
-- PostgreSQL database dump
--

-- Dumped from database version 10.6 (Ubuntu 10.6-0ubuntu0.18.04.1)
-- Dumped by pg_dump version 10.6 (Ubuntu 10.6-0ubuntu0.18.04.1)
-- Edited by author

CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA public;
COMMENT ON EXTENSION "uuid-ossp" IS 'generate universally unique identifiers (UUIDs)';


-- *****TABLE DOCS***** --
CREATE TABLE public.docs (
    name text,
    mime text,
    public boolean,
    created_at timestamp without time zone DEFAULT now(),
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    author text
);

ALTER TABLE ONLY public.docs
    ADD CONSTRAINT docs_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.docs
    ADD CONSTRAINT docs_author_fkey FOREIGN KEY (author) REFERENCES public.users(login);


-- *****TABLE USERS***** --
CREATE TABLE public.users (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    login text,
    password text
);

ALTER TABLE ONLY public.users
    ADD CONSTRAINT login_unique UNIQUE (login);

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


-- *****TABLE PERMITS***** --
CREATE TABLE public.permits (
    docid uuid,
    login text
);

ALTER TABLE ONLY public.permits
    ADD CONSTRAINT permits_docid_fkey FOREIGN KEY (docid) REFERENCES public.docs(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.permits
    ADD CONSTRAINT permits_login_fkey FOREIGN KEY (login) REFERENCES public.users(login);


-- *****TABLE SESSIONS***** --
CREATE TABLE public.sessions (
    id uuid DEFAULT public.uuid_generate_v4(),
    login text,
    token text,
    lastactivitytime timestamp without time zone DEFAULT now()
);


--
-- PostgreSQL database dump complete
--

