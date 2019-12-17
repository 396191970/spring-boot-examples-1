package com.neo;

import de.codecentric.boot.admin.server.config.AdminServerProperties;
import de.codecentric.boot.admin.server.config.EnableAdminServer;
import de.codecentric.boot.admin.server.domain.entities.InstanceRepository;
import de.codecentric.boot.admin.server.notify.CompositeNotifier;
import de.codecentric.boot.admin.server.notify.Notifier;
import de.codecentric.boot.admin.server.notify.RemindingNotifier;
import de.codecentric.boot.admin.server.notify.filter.FilteringNotifier;
import de.codecentric.boot.admin.server.web.client.HttpHeadersProvider;
import de.codecentric.boot.admin.server.web.client.InstanceExchangeFilterFunction;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

import java.time.Duration;
import java.util.Collections;
import java.util.List;

@Configuration
@EnableAutoConfiguration
@EnableAdminServer
@Slf4j
public class AdminServerApplication {

	public static void main(String[] args) {
		SpringApplication.run(AdminServerApplication.class, args);
	}


	// tag::configuration-spring-security[]
	@Configuration
	public static class SecuritySecureConfig extends WebSecurityConfigurerAdapter {
		private final String adminContextPath;

		public SecuritySecureConfig(AdminServerProperties adminServerProperties) {
			this.adminContextPath = adminServerProperties.getContextPath();
		}

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			SavedRequestAwareAuthenticationSuccessHandler successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
			successHandler.setTargetUrlParameter("redirectTo");
			successHandler.setDefaultTargetUrl(adminContextPath + "/");

			http.authorizeRequests()
					.antMatchers(adminContextPath + "/assets/**").permitAll() // <1>
					.antMatchers(adminContextPath + "/login").permitAll()
					.anyRequest().authenticated() // <2>
					.and()
					.formLogin().loginPage(adminContextPath + "/login").successHandler(successHandler).and() // <3>
					.logout().logoutUrl(adminContextPath + "/logout").and()
					.httpBasic().and() // <4>
					.csrf()
					.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())  // <5>
					.ignoringAntMatchers(
							adminContextPath + "/instances",   // <6>
							adminContextPath + "/actuator/**"  // <7>
					);
			// @formatter:on
		}
	}
	// end::configuration-spring-security[]

	// tag::customization-instance-exchange-filter-function[]
	@Bean
	public InstanceExchangeFilterFunction auditLog() {
		return (instance, request, next) -> {
			if (HttpMethod.DELETE.equals(request.method()) || HttpMethod.POST.equals(request.method())) {
				log.info("{} for {} on {}", request.method(), instance.getId(), request.url());
			}
			return next.exchange(request);
		};
	}
	// end::customization-instance-exchange-filter-function[]


	// tag::customization-http-headers-providers[]
	@Bean
	public HttpHeadersProvider customHttpHeadersProvider() {
		return  instance -> {
			HttpHeaders httpHeaders = new HttpHeaders();
			httpHeaders.add("X-CUSTOM", "My Custom Value");
			return httpHeaders;
		};
	}

}
