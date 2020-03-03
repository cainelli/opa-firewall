package firewall

// PolicyEvents ...
func PolicyEvents() []PolicyEvent {
	return []PolicyEvent{
		PolicyEvent{
			Name: "supplier",
			Rego: `
			package supplier

			deny {
				input.host = "supplier.domain.com"
				data.blacklist[_] = input.ip
			}

			deny {
				input.headers["x-gyg-user-id"] = "cainelli"
			}

			deny {
				input.host = "supplier.domain.com"
				input.path = "/login"
			}

			allow {
				input.host = "supplier.domain.com"
				input.ip = "2.2.2.2"
			}`,
			Data: map[string]interface{}{
				"blacklist": []string{"1.1.1.1"},
			},
		},
		PolicyEvent{
			Name: "partner",
			Rego: `
			package partner

			deny {
				input.host = "api.domain.com"
				data.partner.blacklist[_] = input.ip
			}

			deny {
				input.host = "api.domain.com"
				input.path = "/login"
			}

			allow {
				input.host = "api.domain.com"
				input.ip = "2.2.2.2"
			}`,
			Data: map[string]interface{}{
				"blacklist": []string{"3.3.3.3"},
			},
		},
	}
}
