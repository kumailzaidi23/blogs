interface Project {
  title: string
  description: string
  href?: string
  imgSrc?: string
}

const projectsData: Project[] = [
  {
    title: 'TheCyberThesis',
    description: `I developed and deployed a landing page for my cybersecurity startup named TheCyberThesis.`,
    imgSrc: '/static/images/projects/thecyberthesis.png',
    href: 'https://www.thecyberthesis.com',
  },

]

export default projectsData
