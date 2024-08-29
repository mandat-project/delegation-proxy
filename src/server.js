import log from 'npmlog';
import app from './app.js';

const port = 3000;

// Start the server
app.listen(port, () => {
  log.info('DDP', `Listening at http://localhost:${port}`);
});