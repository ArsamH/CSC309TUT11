.PHONY: clean install run zip

DIRNAME := $(notdir $(CURDIR))
ZIPFILE := t8-$(DIRNAME).zip

run:
	node src/index.js

install:
	npm install
	npx prisma generate
	npx prisma db push
	node prisma/seed.js

clean:
	rm -rf node_modules package-lock.json *~ prisma/dev* .env

zip: clean
	zip -r ../$(ZIPFILE) .

