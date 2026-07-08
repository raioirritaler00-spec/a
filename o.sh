#!/bin/bash
# Salvar como compile.sh

echo "Compilando bot otimizado..."

# Verificar se tem zlib
if ! pkg-config --exists zlib; then
    echo "Instalando dependências..."
    apt-get update && apt-get install -y zlib1g-dev gcc make
fi

# Compilar
gcc -O3 -march=native -mtune=native -flto -funroll-loops \
    -fomit-frame-pointer -fprefetch-loop-arrays \
    -fno-stack-protector \
    -pipe -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 \
    -pthread -lm -lz \
    -o bot bot.c

# Verificar se compilou
if [ -f "bot" ]; then
    echo "Compilação concluída!"
    strip bot  # Remove símbolos de debug
    ls -lh bot
else
    echo "Erro na compilação!"
fi
