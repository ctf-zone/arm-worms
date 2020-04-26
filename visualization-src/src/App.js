import React, { useEffect, useRef, useState } from 'react';
import ForceGraph3D from 'react-force-graph-3d';
import ForceGraph2D from 'react-force-graph-2d';
import * as d3 from 'd3';
import * as THREE from 'three';
import graphMap from './map';
import replay from './replay';
// import lcbc from './teams/lcbc.jpg';
import { AlwaysStencilFunc } from 'three';

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const asyncForEach = async (array, callback) => {
  for (let index = 0; index < array.length; index++) {
    if (array[index].length !== 0) {
      await delay(100);
      await callback(array[index]);
    }
  }
};

export default function Index() {
  const fgRef = useRef(null);

  const [data, setData] = useState(graphMap);
  const [ticks, setTicks] = useState(Infinity);
  const [color, setColor] = useState('#0F0');

  const [toggleLinkColor, setToggleLinkColor] = React.useState(true);

  // setTimeout(() => {
  //   setTicks(0);
  //   const newData = {
  //     ...graphMap,
  //     links: graphMap.links.map((link) => ({ ...link, particle: false })),
  //   };
  //   setData(newData);
  // }, 8000);

  useEffect(() => {
    const fg = fgRef.current;
    setTicks(0);
    setTimeout(() => setColor('#0FF'), 7000);

    // Deactivate existing forces
    fg.d3Force('link').distance(200);
    fg.zoom(0.3);
    // fg.d3Force('horizontal', d3.forceX(42));

    asyncForEach(replay, (round) => {
      console.log(round);
      round.forEach(async (teamTurn) => {
        const emittedLink = data.links.find(
          (link) => link.source.id === teamTurn.source
        );
        fgRef.current.emitParticle(emittedLink);
        await delay(300);
        fgRef.current.emitParticle(emittedLink);
        await delay(300);
        fgRef.current.emitParticle(emittedLink);
        await delay(300);
        fgRef.current.emitParticle(emittedLink);
        await delay(300);
        fgRef.current.emitParticle(emittedLink);
        await delay(300);
      });
    });
    // setTimeout(
    //   () =>
    //     replay.forEach((iteration) =>
    //       iteration.forEach((turn) =>
    //         fgRef.current.emitParticle(
    //           delay(1000)
    //           data.links.find((link) => link.source.id === turn.source)
    //         )
    //       )
    //     ),
    //   6000
    // );
  }, [data]);
  return (
    <div>
      <input
        type="checkbox"
        checked={toggleLinkColor}
        onChange={() => setToggleLinkColor(!toggleLinkColor)}
      />{' '}
      Toggle Link Color
      <ForceGraph2D
        ref={fgRef}
        graphData={data}
        forceEngine="d3"
        d3AlphaDecay={0.00005}
        d3VelocityDecay={0.3}
        cooldownTicks={ticks}
        warmupTicks={3000}
        cooldownTime={10000}
        backgroundColor="#20232a"
        nodeColor="#61dafb"
        // linkColor={() => '#F00'}
        linkColor={() => (toggleLinkColor ? 'blue' : 'red')}
        linkOpacity={1}
        linkDirectionalParticles={(d) => d.particle}
        linkDirectionalParticleSpeed={(d) => 0.02}
        linkDirectionalParticleWidth={10}
        linkDirectionalParticleColor={(link) => color}
        onLinkClick={(link) => {
          console.log(link);
          fgRef.current.emitParticle(link);
        }}
        // nodeCanvasObject={(node, ctx, globalScale) => {
        //   const label = node.id;
        //   const fontSize = 12/globalScale;
        //   ctx.font = `${fontSize}px Sans-Serif`;
        //   const textWidth = ctx.measureText(label).width;
        //   const bckgDimensions = [textWidth, fontSize].map(n => n + fontSize * 0.2); // some padding

        //   ctx.fillStyle = 'rgba(255, 255, 255, 0.8)';
        //   ctx.fillRect(node.x - bckgDimensions[0] / 2, node.y - bckgDimensions[1] / 2, ...bckgDimensions);

        //   ctx.textAlign = 'center';
        //   ctx.textBaseline = 'middle';
        //   ctx.fillStyle = node.color;
        //   ctx.fillText(label, node.x, node.y);
        // }}
        nodeCanvasObject={(node, ctx, globalScale) => {
          if (node.team_name !== '') {
            const label = node.team_name;
            const fontSize = 12 / globalScale;
            ctx.font = `${fontSize}px Sans-Serif`;
            const textWidth = ctx.measureText(label).width;
            const bckgDimensions = [textWidth, fontSize].map(
              (n) => n + fontSize * 0.2
            ); // some padding

            ctx.fillStyle = 'rgba(255, 255, 255, 0.8)';
            ctx.fillRect(
              node.x - bckgDimensions[0] / 2,
              node.y - bckgDimensions[1] / 2,
              ...bckgDimensions
            );

            ctx.textAlign = 'center';
            ctx.textBaseline = 'middle';
            ctx.fillStyle = '#F00';
            ctx.fillText(label, node.x, node.y);
          }
        }}
      />
    </div>
  );
}
