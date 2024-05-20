package com.foysalSpring.pma.security;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

	@Autowired
	DataSource dataSource;
	
	@Autowired
	BCryptPasswordEncoder bCryptEncoder;

//	@Bean
//	public SecurityFilterChain configure(AuthenticationManagerBuilder auth) throws Exception {
//		auth.jdbcAuthentication()
//			.usersByUsernameQuery("SELECT username, password, enabled "+
//					"FROM user_accounts WHERE username = ?")
//			.authoritiesByUsernameQuery("SELECT username, role "+
//					"FROM user_accounts WHERE username = ?")
//			.dataSource(dataSource)
//			.passwordEncoder(bCryptEncoder);
//		return auth;
//
//	}


	@Bean
	public SecurityFilterChain configure(HttpSecurity http) throws Exception {
		http
				.csrf(AbstractHttpConfigurer::disable)
				.authorizeHttpRequests(authz -> authz
//			.requestMatchers("/projects/new").hasRole("ADMIN")
//			.requestMatchers("/projects/save").hasRole("ADMIN")
//			.requestMatchers("/employees/new").hasRole("ADMIN")
//			.requestMatchers("/employees/save").hasRole("ADMIN")
//			.requestMatchers("/h2-console/**").permitAll()
						.requestMatchers("/", "/**").permitAll())
				.formLogin(formLogin -> formLogin
						.loginPage("/login") //enable this to go to your own custom login page
						.loginProcessingUrl("/") //enable this to use login page provided by spring security
						.defaultSuccessUrl("/", true)
						.failureUrl("/login?error")
				)
				.logout(logout -> logout
						.logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
						.logoutSuccessUrl("/login?logout")
				);

		return http.build();       //other configure params.
	}
	
}
