create table public.profiles (
  id uuid primary key references auth.users,
  nome text,
  cpf text,
  telefone text
);

create table public.notes (
  id bigserial primary key,
  owner_id uuid references auth.users,
  conteudo text
);
alter table public.notes enable row level security;

create policy "admins veem tudo" on public.notes for select
  using ((auth.jwt() -> 'user_metadata' ->> 'role') = 'admin');

create policy "dono edita" on public.notes for update
  using (owner_id = auth.uid());

create view public.notes_resumo as
  select owner_id, count(*) as total from public.notes group by owner_id;
