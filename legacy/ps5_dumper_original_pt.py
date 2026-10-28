"""Dumps de processos e de intervalos explícitos do kernel via ps5debug.

PID 0 usa kern_base/kern_read; não usa mapas de processos. Um intervalo de
memória do kernel não é automaticamente um ELF nem o kernel completo.
"""
import argparse
import hashlib
import json
import re
import shutil
import time
from datetime import datetime
from pathlib import Path

from ps5dbg import PS5Debug
from ps5dbg.errors import BadStatus

MIB = 1024 * 1024
LIMITE_KERNEL = 83 * MIB
# Cada bloco é um pedido completo ao payload (o servidor aceita até 1 MiB).
BLOCO = MIB
BLOCO_KERNEL = 256 * 1024  # subir para MIB depois de validar no hardware
INTERVALO_AVISO = 8 * MIB
INTERVALO_MANIFESTO = 2.0  # segundos entre reescritas de mapas.json
MAX_U64 = (1 << 64) - 1
ENDERECO_KERNEL_MIN = 0xffff800000000000  # início do intervalo virtual superior
PROT_BITS = {"r": 1, "w": 2, "x": 4}
PAGINA = 4096  # menor intervalo a que a bisseção chega
# Custo máximo da recuperação: um bloco totalmente ilegível custa ~2*BLOCO/PAGINA pedidos.
MAX_BLOCOS_ILEGIVEIS = 2  # blocos seguidos sem um byte legível antes de abandonar o resto da região
MAX_REGIOES_VAZIAS = 3    # regiões seguidas sem dados antes de passar ao modo económico
NOTA_LACUNAS = ("Em regiões com 'lacunas' o ficheiro contém só os bytes recebidos, por ordem de "
                "endereço e sem preenchimento; cada lacuna [inicio, fim) não consta do ficheiro.")


def guardar_manifesto(pasta, documento):
    temporario = pasta / "mapas.json.tmp"
    temporario.write_text(json.dumps(documento, ensure_ascii=False, indent=2), encoding="utf-8")
    temporario.replace(pasta / "mapas.json")


def validar_leitura(dados, pedido, endereco):
    if not isinstance(dados, (bytes, bytearray)) or not dados or len(dados) > pedido:
        raise RuntimeError(f"Leitura inválida em 0x{endereco:x}: esperado 1..{pedido} bytes")
    return dados


def dividir(endereco, tamanho):
    """Metades alinhadas à página, com a primeira no topo da pilha."""
    metade = max(PAGINA, tamanho // 2 // PAGINA * PAGINA)
    return [(endereco + metade, tamanho - metade), (endereco, metade)]


def ler_bisecando(leitor, endereco, tamanho, erro):
    """Relê um intervalo que o servidor já recusou (`erro`), dividindo-o ao meio.

    Devolve, por ordem de endereço, tuplos (endereco, tamanho, dados, erro): `dados`
    é None e `erro` o BadStatus nos intervalos de até PAGINA bytes que continuam
    ilegíveis. Só BadStatus é recuperável; qualquer outra falha propaga-se.
    """
    if tamanho <= PAGINA:
        return [(endereco, tamanho, None, erro)]
    trechos = []
    pendentes = dividir(endereco, tamanho)
    while pendentes:
        a, n = pendentes.pop()
        try:
            dados = validar_leitura(leitor(a, n), n, a)
        except BadStatus as e:
            if n <= PAGINA:
                trechos.append((a, n, None, e))
            else:
                pendentes.extend(dividir(a, n))
            continue
        trechos.append((a, len(dados), dados, None))
        if len(dados) < n:  # leitura curta: o resto continua por ler
            pendentes.append((a + len(dados), n - len(dados)))
    return trechos


def registar_lacuna(lacunas, inicio, fim, tipo, mensagem):
    """Acrescenta [inicio, fim); funde com a anterior se for contígua e do mesmo erro."""
    if lacunas:
        anterior = lacunas[-1]
        if (int(anterior["fim"], 16) == inicio and anterior["tipo"] == tipo
                and anterior["mensagem"] == mensagem):
            anterior["fim"] = hex(fim)
            anterior["tamanho"] = fim - int(anterior["inicio"], 16)
            return
    lacunas.append(dict(inicio=hex(inicio), fim=hex(fim), tamanho=fim - inicio,
                        tipo=tipo, mensagem=mensagem))


def ler_intervalo(leitor, inicio, tamanho, destino, item, bloco, recuperar=False, economico=False):
    """Grava só bytes recebidos. Uma falha conserva o prefixo e o endereço.

    Com recuperar=True um BadStatus não aborta: o bloco é dividido ao meio até à
    página (ler_bisecando) e o que continua ilegível fica em item["lacunas"].
    Com economico=True, se o primeiro bloco for recusado a região inteira fica como
    lacuna "NaoTentado" (1 pedido); se for lido, a recuperação segue normalmente.
    """
    digest = hashlib.sha256()
    criado = False
    item.update(bytes=0, completo=False, erros=[], lacunas=[])
    inicio_t = time.perf_counter()
    proximo_aviso = INTERVALO_AVISO
    fim = inicio + tamanho
    cursor = inicio  # próximo endereço ainda não tratado (como dados ou como lacuna)
    ilegiveis_seguidos = 0
    try:
        with destino.open("xb") as ficheiro:
            criado = True
            while cursor < fim:
                pedido = min(bloco, fim - cursor)
                try:
                    dados = validar_leitura(leitor(cursor, pedido), pedido, cursor)
                    trechos = [(cursor, len(dados), dados, None)]
                except BadStatus as e:
                    if not recuperar:
                        raise
                    if economico and cursor == inicio:
                        registar_lacuna(item["lacunas"], inicio, fim, "NaoTentado",
                                        f"primeiro bloco recusado em modo económico: {e}")
                        cursor = fim
                        continue
                    trechos = ler_bisecando(leitor, cursor, pedido, e)
                lidos = 0
                for endereco, n, dados, erro in trechos:
                    if dados is None:
                        registar_lacuna(item["lacunas"], endereco, endereco + n,
                                        type(erro).__name__, str(erro))
                    else:
                        ficheiro.write(dados)
                        digest.update(dados)
                        item["bytes"] += n
                        lidos += n
                    cursor = endereco + n
                ilegiveis_seguidos = 0 if lidos else ilegiveis_seguidos + 1
                if ilegiveis_seguidos >= MAX_BLOCOS_ILEGIVEIS and cursor < fim:
                    registar_lacuna(item["lacunas"], cursor, fim, "NaoTentado",
                                    f"abandonado após {ilegiveis_seguidos} blocos ilegíveis seguidos")
                    cursor = fim
                if item["bytes"] >= proximo_aviso:
                    decorrido = max(time.perf_counter() - inicio_t, 1e-9)
                    print(f"[*] {item['bytes'] / MIB:.0f} MiB gravados "
                          f"({item['bytes'] / MIB / decorrido:.1f} MiB/s)", flush=True)
                    proximo_aviso = (item["bytes"] // INTERVALO_AVISO + 1) * INTERVALO_AVISO
            item["completo"] = not item["lacunas"]
    except BaseException as e:
        item["erros"].append(dict(endereco=hex(cursor), tipo=type(e).__name__, mensagem=str(e)))
        raise
    finally:
        item["sha256"] = digest.hexdigest()
        if criado and destino.exists() and destino.stat().st_size == 0:
            destino.unlink()
            item["ficheiro"] = None


def extrair(ps5, pid, mapas, pasta):
    if pid == 0:
        raise ValueError("PID 0 exige extrair_kernel(), não mapas de processos")
    documento = dict(tipo="processo", pid=pid, bytes=0, nota=NOTA_LACUNAS, regioes=[])
    acumulado = 0
    ultima_escrita = float("-inf")
    vazias_seguidas = 0
    try:
        for m in mapas:
            if not (m.prot & 1) or m.end <= m.start:
                continue
            nome = f"{m.start:016x}-{m.end:016x}.bin"
            item = dict(nome=m.name, inicio=hex(m.start), fim=hex(m.end), prot=m.prot,
                        ficheiro=nome, bytes=0, completo=False, erros=[], lacunas=[])
            documento["regioes"].append(item)
            print(f"[*] {m.name}: 0x{m.start:x}-0x{m.end:x}", flush=True)
            try:
                # Com várias regiões seguidas sem dados (processo morto, ligação inútil) o
                # primeiro bloco recusado abandona a região: 1 pedido em vez de ~1000.
                ler_intervalo(lambda a, n: ps5.read(pid, a, n), m.start, m.end-m.start,
                              pasta/nome, item, BLOCO, recuperar=True,
                              economico=vazias_seguidas >= MAX_REGIOES_VAZIAS)
                if item["lacunas"]:
                    em_falta = sum(l["tamanho"] for l in item["lacunas"])
                    print(f"[-] {m.name}: {len(item['lacunas'])} lacuna(s), {em_falta} bytes ilegíveis")
            finally:
                acumulado += item["bytes"]
                if item["bytes"]:
                    if vazias_seguidas >= MAX_REGIOES_VAZIAS:
                        print("[*] Modo económico terminado: houve uma região com dados")
                    vazias_seguidas = 0
                else:
                    vazias_seguidas += 1
                    if vazias_seguidas == MAX_REGIOES_VAZIAS:
                        print(f"[*] {MAX_REGIOES_VAZIAS} regiões seguidas sem dados: modo económico "
                              "(região com o primeiro bloco recusado é abandonada sem bisseção)")
                agora = time.monotonic()
                if agora - ultima_escrita >= INTERVALO_MANIFESTO:
                    documento["bytes"] = acumulado
                    guardar_manifesto(pasta, documento)
                    ultima_escrita = agora
    finally:
        documento["bytes"] = sum(r["bytes"] for r in documento["regioes"])
        guardar_manifesto(pasta, documento)
    return documento["bytes"], documento["regioes"]


def validar_intervalo_kernel(inicio, tamanho):
    if not isinstance(inicio, int) or isinstance(inicio, bool):
        raise ValueError("O endereço tem de ser um inteiro de 64 bits")
    if inicio < ENDERECO_KERNEL_MIN or inicio > MAX_U64:
        raise ValueError("O endereço não está no intervalo virtual superior de 64 bits")
    if not isinstance(tamanho, int) or isinstance(tamanho, bool) or tamanho <= 0:
        raise ValueError("O tamanho do kernel deve ser pelo menos 1 byte")
    if inicio + tamanho - 1 > MAX_U64:
        raise ValueError("O intervalo ultrapassa o limite de endereços de 64 bits")


def extrair_kernel(ps5, pasta, tamanho=LIMITE_KERNEL, inicio=None):
    """Lê um intervalo; a base devolvida pelo protocolo é a base .data."""
    # Validar tamanho/endereço explícito antes de enviar qualquer comando.
    validar_intervalo_kernel(ENDERECO_KERNEL_MIN if inicio is None else inicio, tamanho)
    tamanho = min(tamanho, LIMITE_KERNEL)
    base_dados = ps5.kern_base()
    validar_intervalo_kernel(base_dados, 1)
    endereco = base_dados if inicio is None else inicio
    validar_intervalo_kernel(endereco, tamanho)
    nome = f"kernel_{endereco:016x}-{endereco+tamanho:x}.bin"
    item = dict(nome="kernel_data_region" if inicio is None else "kernel_explicit_region",
                inicio=hex(endereco), fim=hex(endereco+tamanho),
                prot=None, ficheiro=nome, bytes=0, completo=False, erros=[])
    documento = dict(tipo="kernel", pid=0, base_dados_kernel=hex(base_dados),
                     origem_base="CMD_KERN_BASE: base .data, não início ELF",
                     kernel_completo=False, tamanho_pedido=tamanho,
                     bloco=BLOCO_KERNEL, bytes=0, regioes=[item],
                     nota="Intervalo solicitado; permissões e mapa integral não foram obtidos. Captura sequencial, não atómica.")
    guardar_manifesto(pasta, documento)
    print(f"[+] Base .data do kernel: 0x{base_dados:x}")
    print(f"[*] Intervalo: 0x{endereco:x}-0x{endereco+tamanho:x} ({tamanho/MIB:.2f} MiB)")
    print("[*] Modo kernel: CMD_KERN_READ, sem CMD_PROC_MAPS.")
    try:
        ler_intervalo(ps5.kern_read, endereco, tamanho, pasta/nome, item, BLOCO_KERNEL)
    finally:
        documento["bytes"] = item["bytes"]
        guardar_manifesto(pasta, documento)
    return documento["bytes"], documento["regioes"]


def filtrar_regioes(regioes, prot_exigida=0, nome=None, max_mib=None):
    """Aplica os filtros opcionais da linha de comandos às regiões legíveis."""
    nome = nome.lower() if nome else None
    return [m for m in regioes
            if (m.prot & prot_exigida) == prot_exigida
            and (nome is None or nome in m.name.lower())
            and (max_mib is None or m.end - m.start <= max_mib * MIB)]


def criar_pasta(nome, saida=None, necessario=0):
    if saida is not None:
        pasta = Path(saida).expanduser().resolve()
    else:
        pasta = Path(__file__).resolve().parent / "dumps" / f"{nome}_{datetime.now():%Y%m%d_%H%M%S_%f}"
    if necessario:
        base = next(p for p in (pasta, *pasta.parents) if p.exists())
        livre = shutil.disk_usage(base).free
        if livre < necessario:
            raise OSError(f"Espaço insuficiente em {base}: "
                          f"{livre / MIB:.0f} MiB livres, {necessario / MIB:.0f} MiB necessários")
    pasta.mkdir(parents=True, exist_ok=False)
    print(f"[*] Destino: {pasta}", flush=True)
    return pasta


def listar_binarios(pasta):
    pasta = Path(pasta).expanduser().resolve()
    if not pasta.is_dir():
        raise ValueError("A pasta de origem não existe")
    def ordem_natural(caminho):
        return tuple((0, int(parte)) if parte.isdigit() else (1, parte.lower())
                     for parte in re.split(r"(\d+)", caminho.name))
    return sorted((p for p in pasta.iterdir() if p.is_file() and p.suffix.lower() == ".bin"),
                  key=ordem_natural)


def concatenar_ficheiros(ficheiros, destino):
    """Concatenação literal: não repõe intervalos de memória nem lacunas."""
    ficheiros = [Path(p).expanduser().resolve() for p in ficheiros]
    destino = Path(destino).expanduser().resolve()
    if not ficheiros:
        raise ValueError("Não há ficheiros .bin para concatenar")
    if len(set(ficheiros)) != len(ficheiros):
        raise ValueError("A lista contém ficheiros repetidos")
    if destino in ficheiros:
        raise ValueError("O destino não pode ser um dos ficheiros de origem")
    if destino.exists():
        raise FileExistsError(f"O destino já existe: {destino}")
    tamanhos = [p.stat().st_size for p in ficheiros]
    total = sum(tamanhos)
    if shutil.disk_usage(destino.parent).free < total:
        raise OSError("Espaço insuficiente para concatenar os ficheiros")
    print("[*] Ordem de concatenação:")
    for indice, (origem, tamanho) in enumerate(zip(ficheiros, tamanhos), 1):
        print(f"  {indice}. {origem.name} ({tamanho} bytes)")
    print("[*] Junção literal dos bytes; não reconstrói endereços ou lacunas de memória.")
    digest = hashlib.sha256()
    gravados = 0
    with destino.open("xb") as saida:
        for origem, esperado in zip(ficheiros, tamanhos):
            lidos = 0
            with origem.open("rb") as entrada:
                while dados := entrada.read(MIB):
                    lidos += len(dados)
                    if lidos > esperado:
                        raise RuntimeError(f"A origem mudou durante a leitura: {origem}")
                    saida.write(dados)
                    digest.update(dados)
                    gravados += len(dados)
            if lidos != esperado:
                raise RuntimeError(f"A origem mudou durante a leitura: {origem}")
    print(f"[+] Concatenados {len(ficheiros)} ficheiros: {gravados} bytes")
    print(f"[+] Destino: {destino}")
    print(f"[+] SHA-256: {digest.hexdigest()}")
    return gravados


def menu_concatenar():
    try:
        entrada = input("[?] Pasta com os ficheiros .bin (Enter = cancelar): ").strip().strip('"')
        if not entrada:
            return
        pasta = Path(entrada).expanduser().resolve()
        ficheiros = listar_binarios(pasta)
        if not ficheiros:
            print("[-] Não foram encontrados ficheiros .bin nessa pasta.")
            return
        for indice, origem in enumerate(ficheiros, 1):
            print(f"  {indice}. {origem.name} ({origem.stat().st_size} bytes)")
        ordem = input("[?] Ordem pelos números, separados por espaços (Enter = todos nesta ordem): ").strip()
        if ordem:
            indices = [int(n) for n in ordem.split()]
            if len(set(indices)) != len(indices) or any(n < 1 or n > len(ficheiros) for n in indices):
                raise ValueError("Escolha números válidos, sem repetições")
            ficheiros = [ficheiros[n - 1] for n in indices]
        predefinido = pasta.parent / f"{pasta.name}_concatenado.bin"
        nome = input(f"[?] Ficheiro final [{predefinido}]: ").strip().strip('"')
        concatenar_ficheiros(ficheiros, nome or predefinido)
    except Exception as erro:
        print(f"[-] Falha na concatenação: {type(erro).__name__}: {erro}")
        print("[*] Se a escrita já tinha começado, o destino pode estar parcial.")


def escolher_processo(ps5):
    """Atualiza a lista a pedido; NOVO significa observado desde a última consulta.

    PID/nome não fornecem a hora real de criação e podem ser reutilizados.
    """
    anteriores = None
    atualizar = True
    procs = []
    while True:
        if atualizar:
            procs = list(ps5.procs())
            atuais = {(p.pid, p.name) for p in procs}
            novos = atuais - anteriores if anteriores is not None else set()
            terminados = anteriores - atuais if anteriores is not None else set()
            procs.sort(key=lambda p: ((p.pid, p.name) not in novos, p.pid))
            print(f"\n[*] Lista atualizada às {datetime.now():%H:%M:%S}: {len(procs)} processos")
            if anteriores is not None:
                print(f"[*] {len(novos)} novos; {len(terminados)} deixaram de constar da lista")
            print("PID    | PROCESSO")
            for p in procs:
                marca = " [NOVO]" if (p.pid, p.name) in novos else ""
                print(f"{p.pid:<6} | {p.name}{marca}")
            if not procs:
                print("[*] Nenhum processo devolvido. Use R para tentar atualizar.")
            anteriores = atuais
            atualizar = False
        entrada = input("[?] PID (0 = kernel) | R = refresh | C = concatenar | sair: ").strip()
        if not entrada or entrada.lower() in ("sair", "q"):
            return None, procs
        if entrada.lower() in ("c", "concatenar"):
            menu_concatenar()
            continue
        if entrada.lower() in ("r", "refresh"):
            atualizar = True
            continue
        try:
            pid = int(entrada)
        except ValueError:
            print("[-] Introduza um PID, R para atualizar, C para concatenar ou sair.")
            continue
        if pid < 0 or (pid != 0 and not any(p.pid == pid for p in procs)):
            print("[-] Esse PID não consta da lista. Use R para atualizar.")
            continue
        return pid, procs


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ip", help="IP da PS5; se omitido, é pedido antes da ligação")
    parser.add_argument("--kernel", action="store_true", help="ler intervalo do kernel, sem PID/maps")
    parser.add_argument("--size-mib", type=int, default=None, help="tamanho em MiB (>= 1); predefinido e máximo 83 no kernel")
    parser.add_argument("--start", type=lambda s: int(s, 0), help="endereço explícito, por exemplo 0xffff...")
    parser.add_argument("--output", help="nova pasta de destino; não substitui pastas existentes")
    parser.add_argument("--pid", type=int, help="PID a extrair (0 = kernel); dispensa o menu interativo")
    parser.add_argument("--prot", help="só regiões com todas estas permissões, por exemplo x ou rw (só processos)")
    parser.add_argument("--name", help="só regiões cujo nome contém este texto, sem maiúsculas/minúsculas (só processos)")
    parser.add_argument("--max-region-mib", type=int, help="saltar regiões maiores que N MiB (só processos)")
    parser.add_argument("--concat", metavar="PASTA", help="concatenar os .bin da pasta sem ligar à PS5")
    parser.add_argument("--concat-output", metavar="FICHEIRO", help="destino da concatenação (novo ficheiro)")
    args = parser.parse_args(argv)
    if args.concat_output and not args.concat:
        parser.error("--concat-output exige --concat")
    if args.concat:
        if any((args.ip is not None, args.kernel, args.pid is not None, args.start is not None,
                args.size_mib is not None, args.output is not None, args.prot is not None,
                args.name is not None, args.max_region_mib is not None)):
            parser.error("--concat não pode ser combinado com opções de dump")
        try:
            origem = Path(args.concat).expanduser().resolve()
            destino = args.concat_output or origem.parent / f"{origem.name}_concatenado.bin"
            concatenar_ficheiros(listar_binarios(origem), destino)
            return 0
        except KeyboardInterrupt:
            print("\n[-] Concatenação interrompida; o destino pode estar parcial.")
            return 130
        except Exception as erro:
            print(f"[-] Falha na concatenação: {type(erro).__name__}: {erro}")
            return 1
    if args.size_mib is not None and args.size_mib < 1:
        parser.error("--size-mib deve ser pelo menos 1")
    if args.pid is not None and args.pid < 0:
        parser.error("--pid não pode ser negativo")
    if args.kernel and args.pid not in (None, 0):
        parser.error("--kernel é incompatível com --pid diferente de 0")
    if args.prot is not None and not re.fullmatch(r"[rwx]+", args.prot):
        parser.error("--prot aceita apenas as letras r, w e x")
    if args.max_region_mib is not None and args.max_region_mib < 1:
        parser.error("--max-region-mib deve ser pelo menos 1")
    prot_exigida = sum(PROT_BITS[c] for c in set(args.prot or ""))
    usa_filtros = any(v is not None for v in (args.prot, args.name, args.max_region_mib))
    pasta = None
    operacao = "ligação"
    try:
        if args.ip is None:
            while not args.ip:
                args.ip = input("[?] IP da PS5 (C = concatenar ficheiros): ").strip()
                if args.ip.lower() in ("c", "concatenar"):
                    menu_concatenar()
                    args.ip = None
                    continue
                if not args.ip:
                    print("[-] Introduza o IP da PS5 para continuar.")
        else:
            args.ip = args.ip.strip()
            if not args.ip:
                raise ValueError("--ip não pode estar vazio")
        with PS5Debug(args.ip, timeout=10) as ps5:
            print(f"\n[+] Ligado à PS5 ({args.ip})")
            kernel = args.kernel or args.pid == 0
            nao_interativo = args.kernel or args.pid is not None
            if not kernel:
                operacao = "lista de processos"
                if args.pid is None:
                    pid, procs = escolher_processo(ps5)
                    if pid is None:
                        return 0
                    kernel = pid == 0
                else:
                    procs = sorted(ps5.procs(), key=lambda p: p.pid)
                    pid = args.pid
            if kernel:
                if usa_filtros:
                    raise ValueError("--prot/--name/--max-region-mib aplicam-se apenas a processos")
                operacao = "leitura do kernel"
                quantidade = args.size_mib
                if quantidade is None:
                    quantidade = 83 if nao_interativo else int(input("[?] Tamanho em MiB [83; máximo 83]: ").strip() or "83")
                if quantidade < 1:
                    raise ValueError("Tamanho deve ser pelo menos 1 MiB")
                if quantidade * MIB > LIMITE_KERNEL:
                    print("[*] Tamanho limitado a 83 MiB para o dump do kernel.")
                    quantidade = LIMITE_KERNEL // MIB
                # Validar o intervalo limitado antes de criar a pasta.
                validar_intervalo_kernel(ENDERECO_KERNEL_MIN if args.start is None else args.start, quantidade*MIB)
                operacao = "criação da pasta de destino"
                pasta = criar_pasta("kernel_0", args.output, necessario=quantidade*MIB)
                operacao = "leitura do kernel"
                t_inicio = time.perf_counter()
                total, regioes = extrair_kernel(ps5, pasta, quantidade*MIB, args.start)
            else:
                if args.start is not None or args.size_mib is not None:
                    raise ValueError("--start/--size-mib aplicam-se apenas ao modo kernel")
                alvo = next((p for p in procs if p.pid == pid), None)
                if alvo is None:
                    raise ValueError("Esse PID não consta da lista de processos")
                operacao = f"mapas do PID {pid}"
                mapas = list(ps5.maps(pid))
                legiveis = [m for m in mapas if m.prot & 1 and m.end > m.start]
                print(f"[*] {len(mapas)} regiões, {len(legiveis)} com leitura")
                if not legiveis:
                    print("[-] Nenhuma região legível foi devolvida pelo servidor")
                    return 1
                selecionadas = filtrar_regioes(legiveis, prot_exigida, args.name, args.max_region_mib)
                if usa_filtros:
                    print(f"[*] {len(selecionadas)} regiões após filtros")
                    if not selecionadas:
                        print("[-] Nenhuma região corresponde aos filtros")
                        return 1
                a_ler = sum(m.end - m.start for m in selecionadas)
                print(f"[*] A ler {a_ler / MIB:.2f} MiB em {len(selecionadas)} regiões")
                nome = re.sub(r"[^A-Za-z0-9_.-]", "_", alvo.name)[:80] or "processo"
                operacao = "criação da pasta de destino"
                pasta = criar_pasta(f"{nome}_{pid}", args.output, necessario=a_ler)
                operacao = f"leitura do PID {pid}"
                t_inicio = time.perf_counter()
                total, regioes = extrair(ps5, pid, selecionadas, pasta)
            decorrido = max(time.perf_counter() - t_inicio, 1e-9)
            incompletas = sum(not r["completo"] for r in regioes)
            print(f"[+] Gravados {total} bytes ({total/MIB:.2f} MiB) em {decorrido:.1f} s "
                  f"({total/MIB/decorrido:.1f} MiB/s); regiões incompletas: {incompletas}")
            lacunas = [l for r in regioes for l in r.get("lacunas", ())]
            if lacunas:
                print(f"[-] {len(lacunas)} lacuna(s), {sum(l['tamanho'] for l in lacunas)} bytes ilegíveis; "
                      "ver 'lacunas' em mapas.json")
            if kernel:
                print("[*] Intervalo do kernel extraído; não representa automaticamente o kernel completo nem um ELF")
            return 0 if total and not incompletas else 1
    except KeyboardInterrupt:
        print("\n[-] Interrompido; dados já gravados conservados")
        return 130
    except BadStatus as e:
        print(f"[-] O payload respondeu mas recusou a operação ({operacao}): {e}")
        print("[*] Verifique o comando/intervalo e o suporte do payload; não é um diagnóstico de IP incorreto")
        return 1
    except Exception as e:
        print(f"[-] Falha em {operacao}: {type(e).__name__}: {e}")
        return 1
    finally:
        if pasta is not None:
            print(f"[*] Destino indicado: {pasta}; se a leitura começou, consulte mapas.json")


def dumper_interativo():
    return main()


if __name__ == "__main__":
    raise SystemExit(main())
