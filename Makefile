

SOLS_DIR        = contracts
DEPLOY_DIR      = deployed_contracts
DATA_DIR        = src/contracts_data

SOURCE_SOLS     = CTICatalog CTIOperator CTIToken CTIBroker MetemcyberUtil
TARGET_ABIS     = $(SOURCE_SOLS:%=$(DEPLOY_DIR)/Default%.json)
TARGET_COMBINEDS= $(SOURCE_SOLS:%=$(DATA_DIR)/%.combined.json)

SOLC_ARGS       = @openzeppelin/=$(CURDIR)/node_modules/@openzeppelin/
SOLC_COMMAND    = solc $(SOLC_ARGS) --optimize


all: combined

.PHONY: abi combined
abi: $(TARGET_ABIS)
combined: $(TARGET_COMBINEDS)

$(DEPLOY_DIR)/Default%.json: $(SOLS_DIR)/%.sol
	( cd $(SOLS_DIR) \
	  && ($(SOLC_COMMAND) --abi $*.sol \
	      | grep -A2 "^======= $*.sol:" \
	      | tail -1 \
	     ) \
	) > $@

$(DATA_DIR)/%.combined.json: $(SOLS_DIR)/%.sol
	mkdir -p $(DATA_DIR)
	( cd $(SOLS_DIR) \
	  && $(SOLC_COMMAND) --combined-json bin,metadata $*.sol \
	) > $@

.PHONY: clean
clean:
	rm -f $(TARGET_ABIS) $(TARGET_COMBINEDS)

.PHONY: abi-earth
abi-earth:
	earth +solc
