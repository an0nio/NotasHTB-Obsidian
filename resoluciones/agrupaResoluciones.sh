#!/bin/bash


# Buscar y procesar cada archivo resolution.md
locate /resolution.md | while read filepath; do
  # Leer la primera línea que contiene el título (empieza con #)
  title=$(grep -m 1 '^#' "$filepath" | sed 's/# //;s/[\/:*?"<>|]//g')

  # Si no hay título, usar un nombre predeterminado
  [ -z "$title" ] && title="Untitled"

  # Agregar un índice si el archivo ya existe para evitar sobrescrituras
  if [ -f "~/resoluciones/$title.md" ]; then
    i=1
    while [ -f "~/resoluciones/${title}_$i.md" ]; do
      ((i++))
    done
    title="${title}_$i"
  fi

  # Copiar el archivo con el nuevo nombre basado en el título
  cp "$filepath" ~/resoluciones/"$title.md"
done
