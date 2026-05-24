#!/bin/bash

TARGET=$1

if [ -z "$TARGET" ]; then
    echo "Uso: ./script.sh alvo.com"
    exit 1
fi

DS_WEBHOOK="XX"

DATE=$(date +%Y-%m-%d)
TARGET_NAME=$(echo "$TARGET" | sed -E 's/^(https?:\/\/)?(www\.)?//' | cut -d/ -f1)
FOLDER_NAME=$(echo "$TARGET_NAME" | cut -d. -f1)

BASE_DIR="../../$FOLDER_NAME"
OUTPUT_FILE="$BASE_DIR/subdomains-$DATE.txt"
INTERESTING_FILE="$BASE_DIR/interesting-$DATE.txt"
SCREENSHOT_DIR="$BASE_DIR/screenshots"

mkdir -p "$SCREENSHOT_DIR"

echo "[+] Iniciando recon para: $TARGET_NAME"
echo "[+] Resultados em: $BASE_DIR"

# -- Reconhecimento

subfinder -d "$TARGET_NAME" -silent | httpx -silent -sc -title -td -follow-redirects -random-agent -retries 2 -o "$OUTPUT_FILE"

# --Validação de SC 

if [ -f "$OUTPUT_FILE" ]; then
    grep -E '\[200\]|\[301\]|\[302\]|\[403\]' "$OUTPUT_FILE" > "$INTERESTING_FILE"
    COUNT=$(wc -l < "$INTERESTING_FILE")
    echo "[+] Encontrados $COUNT hosts interessantes."
else
    echo "[-] Falha ao gerar o arquivo de subdomínios."
    exit 1
fi


LAST_FILE=$(ls -1 "$BASE_DIR"/interesting-*.txt 2>/dev/null | grep -v "$DATE" | sort -r | head -n 1)

if [ -f "$LAST_FILE" ]; then
	echo "[x] Arquivo anterior detectado: $LAST_FILE"
	awk '{print $1}' "$LAST_FILE" | sort -u > "$BASE_DIR/old_urls.tmp"
	awk '{print $1}' "$INTERESTING_FILE" | sort -u > "$BASE_DIR/new_urls.tmp"
	NEW_HOSTS=$(comm -13 "$BASE_DIR/old_urls.tmp" "$BASE_DIR/new_urls.tmp")
	
	if [ ! -z "$NEW_HOSTS" ]; then
		echo "[+] Novos hosts detectados"
		echo "$NEW_HOSTS" > "$BASE_DIR/filtered-$DATE.txt"
		MESSAGE="NOVOS HOSTS DETECTADOS\nAlvo: \`$TARGET_NAME\`\nQuantidade: \`$(echo "$NEW_HOSTS" | wc -l)\`\n\`\`\`text\n$NEW_HOSTS\n\`\`\`"
		gowitness file -f "$BASE_DIR/filtered-$DATE.txt" -P "$SCREENSHOT_DIR" -t 5 --disable-db

	fi
	rm "$BASE_DIR/old_urls.tmp" "$BASE_DIR/new_urls.tmp"
	curl -H "Content-Type: application/json" -X POST -d "{\"content\": \"$MESSAGE\"}" "$DS_WEBHOOK" > /dev/null

else 
	MESSAGE="Primeiro scan finalizado\nAlvo: \`$TARGET_NAME\`\nQuantidade: \`$COUNT\`"
	curl -H "Content-Type: application/json" -X POST -d "{\"content\": \"$MESSAGE\"}" "$DS_WEBHOOK" > /dev/null
	awk '{print $1}' $INTERESTING_FILE > $BASE_DIR/sorted_urls.txt

	gowitness file -f "$BASE_DIR/sorted_urls.txt" -P "$SCREENSHOT_DIR" -t 5 --disable-db

	
fi




