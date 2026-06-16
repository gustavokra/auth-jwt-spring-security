# SecurityContextHolder
Usado para guardar detalhes de quem é autenticado.

Fica dentro de SecurityFilter, após a validação do token ser positiva, o email é retirado do token e tido como __principal__, assim como a role é tida como o gerador da Collection de GrantedAuthority. 

SecurityContextHolder -> SecurityContext -> Authentication(principal, credentials, authorities)
```
UsernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(username.getEmail(), authorities);
SecurityContextHolder.getContext().setAuthentication(authentication)
```

# Security Context
Obtido por meio do SecutiryContextHolder, contém o objeto Authentication.
Usado dentro de SecurityFilter.

# Authentication
Interface que serve para dois propósitos dentro do Spring Security
 1. Fornecer credenciais para __AuthenticationManager__ que um usuário forneceu para autenticacão. IsAuthenticate retorna false. 
 Nesse caso o uso fica no controller, no método de login:

 ```
 UsernamePasswordAuthenticationToken userAndPass = 
    new UsernamePasswordAUthenticationToken(request.email(), request.password());

 Authentication authentication = AuthenticationManager.authenticate(userAndPass)
 ```

 2. Representar o usuario autenticado no momento, a partir do SecurityContext.

São atributos de Authentication:
principal (geralmente uma instancia de user details);
credentials (geralmente é uma senha, em muitos casos apagada após a autenticação para garantir que não seja exposta);
e authorities (instâncias de GrantedAuthority).  

# GrantedAuthority
Permissoes de auto nível
