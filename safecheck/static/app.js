const $ = (id) => document.getElementById(id);
const CORES = ["#ef4444", "#f97316", "#eab308", "#84cc16", "#22c55e"];

function escapar(texto) {
  const d = document.createElement("div");
  d.textContent = texto;
  return d.innerHTML;
}

async function postar(rota, corpo) {
  const r = await fetch(rota, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(corpo),
  });
  return r.json();
}

// ---- senha (analisa enquanto digita, com pequeno atraso)
let timer;
$("senha").addEventListener("input", () => {
  clearTimeout(timer);
  timer = setTimeout(async () => {
    const senha = $("senha").value;
    if (!senha) {
      $("barra-senha").style.width = "0";
      $("res-senha").innerHTML = "";
      return;
    }
    const d = await postar("/api/senha", { senha });
    const cor = CORES[d.pontos];
    $("barra-senha").style.width = ((d.pontos + 1) / 5) * 100 + "%";
    $("barra-senha").style.background = cor;
    $("res-senha").innerHTML =
      `<span class="selo" style="background:${cor}">${escapar(d.nivel)}</span>
       <p>Entropia: ${d.entropia_bits} bits · Tempo para quebrar: ${escapar(d.tempo_para_quebrar)}</p>
       <ul>${d.dicas.map((x) => `<li>${escapar(x)}</li>`).join("")}</ul>`;
  }, 250);
});

$("ver").addEventListener("click", () => {
  const campo = $("senha");
  const mostrar = campo.type === "password";
  campo.type = mostrar ? "text" : "password";
  $("ver").textContent = mostrar ? "Ocultar" : "Mostrar";
});

// ---- url
async function analisarUrl() {
  const d = await postar("/api/url", { url: $("url").value });
  if (d.erro) {
    $("res-url").innerHTML = `<p class="erro">${escapar(d.erro)}</p>`;
    return;
  }
  const cor = { Baixo: "#22c55e", Médio: "#eab308", Alto: "#ef4444" }[d.risco];
  $("res-url").innerHTML =
    `<span class="selo" style="background:${cor}">Risco ${escapar(d.risco)}</span>
     <p>Domínio: <strong>${escapar(d.dominio)}</strong></p>
     <ul>${d.alertas.map((x) => `<li>${escapar(x)}</li>`).join("")}</ul>`;
}
$("btn-url").addEventListener("click", analisarUrl);
$("url").addEventListener("keydown", (e) => e.key === "Enter" && analisarUrl());

// ---- gerador
async function gerar() {
  const t = $("tamanho").value;
  const s = $("simbolos").checked ? 1 : 0;
  const r = await fetch(`/api/gerar?tamanho=${t}&simbolos=${s}`);
  $("senha-gerada").value = (await r.json()).senha;
}
$("btn-gerar").addEventListener("click", gerar);

$("copiar").addEventListener("click", async () => {
  const v = $("senha-gerada").value;
  if (!v) return;
  try {
    await navigator.clipboard.writeText(v);
    $("copiar").textContent = "Copiado!";
  } catch {
    $("senha-gerada").select();
    $("copiar").textContent = "Selecionado";
  }
  setTimeout(() => ($("copiar").textContent = "Copiar"), 1500);
});
