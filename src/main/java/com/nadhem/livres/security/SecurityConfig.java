package com.nadhem.livres.security;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@SuppressWarnings("deprecation")
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter{
	@Override
	 protected void configure(AuthenticationManagerBuilder auth) throws Exception {
	 
	auth.inMemoryAuthentication().withUser("admin").password("{noop}123").roles("ADMIN");
	auth.inMemoryAuthentication().withUser("nadhem").password("{noop}123").roles("AGENT","USER");
	auth.inMemoryAuthentication().withUser("user1").password("{noop}123").roles("USER");
	}
	 
	@Override
	 protected void configure(HttpSecurity http) throws Exception {
	 http.authorizeRequests().antMatchers("/showCreate").hasAnyRole("ADMIN","AGENT");
	 http.authorizeRequests().antMatchers("/saveLivre").hasAnyRole("ADMIN","AGENT");
	 http.authorizeRequests().antMatchers("/listeLivres")
	 .hasAnyRole("ADMIN","AGENT","USER");
	 
	 http.authorizeRequests()
	 .antMatchers("/supprimerLivre","/modifierLivre","/updateLivre")
	 .hasAnyRole("ADMIN");
	 
	 http.authorizeRequests().anyRequest().authenticated();
	 http.formLogin();
	 }
	
}
