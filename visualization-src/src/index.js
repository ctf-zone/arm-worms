import ForceGraph from 'force-graph';
import axios from 'axios';
import './index.css';

const colors = {
  mslc: {
    color: '#e04a3f',
    short: 'LC',
  },
  TSG: {
    color: '#fa01af',
    short: 'TG',
  },
  mhackeroni: {
    color: '#e5b946',
    short: 'MI',
  },
  Bushwhackers: {
    color: '#78b353',
    short: 'BS',
  },
  'Tea Deliverers': {
    color: '#02ec00',
    short: 'TD',
  },
  p4: {
    color: '#075cff',
    short: 'P4',
  },
  'perfect blue': {
    color: '#6686e3',
    short: 'PB',
  },
  '地松鼠.PAS': {
    color: '#a963ba',
    short: 'SP',
  },
  'Dragon Sector': {
    color: '#00d6d8',
    short: 'DS',
  },
  'A*0*E': {
    color: '#864d00',
    short: 'A0E',
  },
};

document.getElementById('reset').addEventListener('click', () => {
  speed = parseInt(document.getElementById('speed').value);
  initFunc();
});

let graphMap,
  replay,
  UUID,
  armNodes,
  miningNodes,
  teamsScores,
  timeoutCheckUUID,
  speed = 10;

const URLstring = window.location.href;
const url = new URL(URLstring);
const checkUUID = url.searchParams.get('check');
const savedUUID = url.searchParams.get('uuid');

//Initialize Graph canvas
let myGraph = ForceGraph();

//API methods
const getMap = async () => {
  const gameId = savedUUID ? savedUUID : UUID;
  return await axios.get(`/json_map/${gameId}`).then(({ data }) => {
    return data;
  });
};

const getReplay = async () => {
  const gameId = savedUUID ? savedUUID : UUID;
  return await axios.get(`/json_replay/${gameId}`).then(({ data }) => {
    return data;
  });
};

const getUUID = async () => {
  clearTimeout(timeoutCheckUUID);
  await axios.get(`/get_last_uuid`).then(({ data }) => {
    if (UUID !== data && UUID !== undefined) {
      document.location.reload(true);
    }
    UUID = data;
    if (checkUUID !== 'true') {
      timeoutCheckUUID = setTimeout(function () {
        getUUID();
      }, 10 * 1000);
    }
  });
};

//Render GraphNodes methods
const drawMiningAreal = (node, ctx, textWidth, fontSize, bckgDimensions) => {
  const bckgDimensionsMining = [textWidth, fontSize].map(
    (n) => n + fontSize * 1 + 30
  );

  ctx.fillStyle = '#FFF';
  ctx.fillRect(
    node.x - bckgDimensions[0] / 2 - 15,
    node.y - bckgDimensions[1] / 2 - 15,
    ...bckgDimensionsMining
  );
};

const drawTeamRect = (node, ctx, bckgDimensions, label) => {
  ctx.fillStyle = colors[armNodes.get(node.id).team_name].color;
  ctx.fillRect(
    node.x - bckgDimensions[0] / 2,
    node.y - bckgDimensions[1] / 2,
    ...bckgDimensions
  );
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillStyle = '#000';
  ctx.fillText(label, node.x, node.y);
};

const drawTeamNode = (node, ctx, label, teamName) => {
  const fontSize = 36;
  ctx.font = `${fontSize}px Sans-Serif`;
  const textWidth = ctx.measureText(label).width;
  const bckgDimensions = [textWidth, fontSize].map((n) => n + fontSize * 1);

  if (
    miningNodes.get(teamName) !== undefined &&
    miningNodes.get(teamName).id === node.id
  ) {
    drawMiningAreal(node, ctx, textWidth, fontSize, bckgDimensions);
    drawTeamRect(node, ctx, bckgDimensions, label);
  } else {
    drawTeamRect(node, ctx, bckgDimensions, label);
  }
};

const drawGraph = (data) => {
  myGraph(document.getElementById('graph'))
    .width(document.getElementById('graph').offsetWidth - 4)
    .height(document.getElementById('graph').offsetHeight - 4)
    .d3AlphaDecay(0.000003)
    .d3VelocityDecay(0.000003)
    .cooldownTicks(0)
    .warmupTicks(10000)
    .nodeColor((node) => {
      return armNodes.get(node.id).team_name ? 'transparent' : '#FFF';
    })
    .nodeRelSize(15)
    .linkColor((link) => '#4d4d4d')
    .linkDirectionalParticleColor((link) => link.color || '#FFF')
    .linkDirectionalParticleWidth(10)
    .nodeCanvasObject((node, ctx, globalScale) => {
      if (node.team_name !== '') {
        const label = colors[node.team_name].short;
        const teamName = node.team_name;
        return drawTeamNode(node, ctx, label, teamName);
      }
      if (armNodes.get(node.id).team_name) {
        const label = colors[armNodes.get(node.id).team_name].short;
        const teamName = armNodes.get(node.id).team_name;
        return drawTeamNode(node, ctx, label, teamName);
      }
      ctx.fillStyle = '#FFF';
      ctx.beginPath();
      ctx.arc(node.x, node.y, 15, 0, 2 * Math.PI, false);
      ctx.fill();
    })
    .backgroundColor('#20232a')
    .graphData(data);

  myGraph.d3Force('link').distance((link) => 500);
  myGraph.zoom(0.25);
};

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const asyncForEach = async (array, callback, delayK) => {
  for (let index = 0; index < array.length; index++) {
    if (array.length > 10 && Array.isArray(array[0])) {
      array[index].forEach((team) =>
        teamsScores.set(team.team_name, {
          team_name: team.team_name,
          score: team.current_score,
        })
      );
      const sortedList = Array.from(teamsScores.values()).sort(
        (a, b) => b.score - a.score
      );
      //Update scores per 10 iterations
      if (index % 10 === 0) {
        for (let i = 0; i < 10; i++) {
          const el = document.getElementsByClassName('place')[i];
          el.style.color = '#FFF';
          el.innerHTML = `<span style="color: ${
            sortedList[i] ? colors[sortedList[i].team_name].color : '#FFF'
          }">${
            sortedList[i] ? sortedList[i].team_name : `Team${i}`
          }</span> Scores: ${sortedList[i] ? sortedList[i].score : 0}`;
        }
      }
    }
    if (array[index].length !== 0) {
      await delay(delayK);
      await callback(array[index]);
    }
  }
};

const initFunc = async () => {
  if (!savedUUID) {
    await getUUID();
  }
  graphMap = await getMap();
  replay = await getReplay();

  armNodes = new Map(graphMap.nodes.map((node) => [node.id, { ...node }]));

  miningNodes = new Map();

  teamsScores = new Map(
    Object.keys(colors).map((team) => [team, { team_name: team, score: 0 }])
  );

  await drawGraph(graphMap);

  if (replay.length !== 0) {
    await asyncForEach(
      replay,
      (round) => {
        asyncForEach(
          round,
          async ({ target, mining, source, team_name }) => {
            const emittedLink = graphMap.links.find(
              (link) => link.source.id === source && link.target.id === target
            );
            if (mining !== 1) {
              myGraph.pushParticle(
                emittedLink.source.id,
                emittedLink.target.id,
                {
                  speed: speed <= 100 ? 0.1 : 10 / speed,
                  color: colors[team_name].color,
                }
              );
              await delay(speed / 10);
              armNodes.set(target, { ...armNodes.get(target), team_name });
            } else {
              miningNodes.set(team_name, {
                id: source,
              });
            }
          },
          speed
        );
      },
      speed
    );
  }
};

initFunc();
