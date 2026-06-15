#Security COntextHolder
usado para guardar detalhes de quem é autenticado

fica dentro de SecurityFilter, após a validação do token ser positiva, o email é retirado do token e tido como princpial, assim como o é tido como a role é tido como o gerador da Collection de GrantedAuthority. 

SecurityContextHolder -> SecurityContext -> Authentication(principal, credentials, authorities)
```
UsernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(username.getEmail(), authorities);
SecurityContextHolder.getContext().setAuthorization(authorization)
```