T = $(wildcard test-*.sh)

test: $(T)
	@$(MAKE) --silent clean

$(T): clean
	./$@ $(TEST_OPTS) -v

clean:
	@rm -fr test-results trash\ directory.*

.PHONY: test $(T) clean
