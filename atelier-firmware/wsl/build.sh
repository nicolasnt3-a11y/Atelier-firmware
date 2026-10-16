#!/usr/bin/env bash
# Compile les outils depuis les dépôts Windows sans jamais écrire dedans :
# moria et mithril sont compilés « à côté » (/opt/fwtools/build), les autres
# sont d'abord copiés dans /opt/fwtools/src (leur compilation génère des
# fichiers dans le dossier source). Lancé en root par l'Atelier.
#
#   build.sh <dossier-des-depots> [--deps] [outil...]
#
# --deps installe d'abord les paquets Ubuntu nécessaires (première installation).
# Sans liste d'outils, tous sont compilés.
set -euo pipefail

REPOS="${1:?usage: build.sh <dossier-des-depots> [--deps] [outil...]}"
shift
BUILD=/opt/fwtools/build
SRC=/opt/fwtools/src
mkdir -p "$BUILD" "$SRC"

if [[ "${1:-}" == "--deps" ]]; then
    shift
    echo ">> Installation des outils de compilation Ubuntu"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq cmake g++ python3 curl unzip tar rsync \
        zlib1g-dev liblzma-dev liblz4-dev libzstd-dev \
        autoconf automake libtool pkg-config \
        cargo rustc clang libfontconfig1-dev libssl-dev         flex libabsl-dev libexpat1-dev libgcrypt20-dev libgpg-error-dev libre2-dev         yara >/dev/null
fi

tools=("$@")
[[ ${#tools[@]} -eq 0 ]] && tools=(moria mithril cpu_rec binbloom binwalk bulk_extractor findcrypt-yara)
jobs=$(( $(nproc) > 8 ? 8 : $(nproc) ))

# Copie propre des sources (sans l'historique git).
copy_src() { rsync -a --delete --exclude .git "$REPOS/$1/" "$SRC/$1/"; }

for tool in "${tools[@]}"; do
    [[ -d "$REPOS/$tool" ]] || { echo "   ($tool absent, ignoré)"; continue; }
    echo ">> Compilation de $tool"
    case "$tool" in
    moria|mithril)
        cmake -S "$REPOS/$tool" -B "$BUILD/$tool" -DCMAKE_BUILD_TYPE=Release >/dev/null
        # Une compilation très parallèle échoue parfois sur WSL : on réessaie en série.
        if ! cmake --build "$BUILD/$tool" -j"$jobs" >/dev/null 2>"$BUILD/$tool.err"; then
            echo "   (nouvel essai en mode lent)"
            cmake --build "$BUILD/$tool" -j1 2>&1 | tail -20
        fi
        install -m755 "$BUILD/$tool/$tool" "/usr/local/bin/$tool"
        "/usr/local/bin/$tool" --version
        ;;
    cpu_rec)
        # Script Python + corpus : il suffit de le copier.
        copy_src cpu_rec
        cat > /usr/local/bin/cpu_rec <<'EOF'
#!/bin/sh
exec python3 /opt/fwtools/src/cpu_rec/cpu_rec.py "$@"
EOF
        chmod 755 /usr/local/bin/cpu_rec
        # Premier appel : prépare les statistiques du corpus (environ 30 s).
        python3 -c "import sys; sys.path.insert(0, '$SRC/cpu_rec'); from cpu_rec import which_arch; which_arch(); print('cpu_rec prêt')"
        ;;
    binbloom)
        copy_src binbloom
        ( cd "$SRC/binbloom" && autoreconf -i >/dev/null 2>&1 && ./configure -q >/dev/null && make -s -j"$jobs" >/dev/null )
        install -m755 "$SRC/binbloom/src/binbloom" /usr/local/bin/binbloom 2>/dev/null \
            || install -m755 "$SRC/binbloom/binbloom" /usr/local/bin/binbloom
        echo "binbloom prêt"
        ;;
    binwalk)
        copy_src binwalk
        # Compilation Rust : longue la première fois (plusieurs minutes).
        # Son script de compilation installe « ruget » dans ~/.cargo/bin et l'appelle ensuite.
        ( cd "$SRC/binwalk" && PATH="$HOME/.cargo/bin:$PATH" \
            cargo build --release --locked --quiet --target-dir "$BUILD/binwalk" )
        install -m755 "$BUILD/binwalk/release/binwalk" /usr/local/bin/binwalk
        binwalk --version 2>/dev/null || true
        ;;
    bulk_extractor)
        copy_src bulk_extractor
        # Sans E01 (libewf) : inutile pour des dumps de puces.
        # Compilation C++ : plusieurs minutes la première fois.
        ( cd "$SRC/bulk_extractor" && ./bootstrap.sh && ./configure -q --disable-libewf             && make -s -j"$jobs" ) >"$BUILD/bulk_extractor.log" 2>&1             || { tail -30 "$BUILD/bulk_extractor.log"; exit 1; }
        install -m755 "$SRC/bulk_extractor/src/bulk_extractor" /usr/local/bin/bulk_extractor
        bulk_extractor -V
        ;;
    findcrypt-yara)
        # Règles YARA (constantes crypto) : simple copie, lues par yara (paquet Ubuntu).
        copy_src findcrypt-yara
        yara --version >/dev/null && echo "règles findcrypt prêtes (yara $(yara --version))"
        ;;
    esac
done
