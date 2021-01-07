package com.gft.gftfood.auth.core;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.gft.gftfood.auth.model.Usuario;
import com.gft.gftfood.auth.model.UsuarioRepository;

@Service
public class JpaUserDetailsService implements UserDetailsService {

	@Autowired
	private UsuarioRepository usuarioRepository;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

		Usuario usuario = usuarioRepository.findByEmail(username)
				.orElseThrow(() -> new UsernameNotFoundException("Usuário não encontrado com e-mail não encontrado"));

		return new AuthUser(usuario);
	}

}
